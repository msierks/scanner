#!/usr/bin/env bash

# A library of CI related reusable bash functions
# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/lib.sh

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$SCRIPTS_ROOT/scripts/lib.sh"

set -euo pipefail

ensure_CI() {
    if ! is_CI; then
        die "A CI environment is required."
    fi
}

ci_export() {
    if [[ "$#" -ne 2 ]]; then
        die "missing args. usage: ci_export <env-name> <env-value>"
    fi

    local env_name="$1"
    local env_value="$2"

    if command -v cci-export >/dev/null; then
        cci-export "$env_name" "$env_value"
    else
        export "$env_name"="$env_value"
    fi
}

ci_exit_trap() {
    local exit_code="$?"
    info "Executing a general purpose exit trap for CI"
    echo "Exit code is: ${exit_code}"

    (send_slack_notice_for_failures_on_merge "${exit_code}") || { echo "ERROR: Could not slack a test failure message"; }

    while [[ -e /tmp/hold ]]; do
        info "Holding this job for debug"
        sleep 60
    done
}

create_exit_trap() {
    trap ci_exit_trap EXIT
}

push_images() {
    info "Pushing images"

    require_environment "QUAY_RHACS_ENG_RW_USERNAME"
    require_environment "QUAY_RHACS_ENG_RW_PASSWORD"
    require_environment "QUAY_STACKROX_IO_RW_USERNAME"
    require_environment "QUAY_STACKROX_IO_RW_PASSWORD"

    local tag
    tag="$(make --quiet --no-print-directory tag)"
    local image_set=("scanner" "scanner-db" "scanner-slim" "scanner-db-slim")

    _push_image_set() {
        local registry="$1"
        local tag="$2"

        for image in "${image_set[@]}"; do
            "$SCRIPTS_ROOT/scripts/push-as-manifest-list.sh" "${registry}/${image}:${tag}" | cat
        done
    }

    _tag_image_set() {
        local registry="$1"
        local tag="$2"

        for image in "${image_set[@]}"; do
            docker tag "${image}:${tag}" "${registry}/${image}:${tag}"
        done
    }

    # Push to us.gcr.io/stackrox-ci
    _tag_image_set "us.gcr.io/stackrox-ci" "$tag"
    _push_image_set "us.gcr.io/stackrox-ci" "$tag"

    # Push to quay.io/rhacs-eng
    docker login -u "$QUAY_RHACS_ENG_RW_USERNAME" --password-stdin <<<"$QUAY_RHACS_ENG_RW_PASSWORD" quay.io
    _tag_image_set "quay.io/rhacs-eng" "$tag"
    _push_image_set "quay.io/rhacs-eng" "$tag"

    # Push to quay.io/stackrox-io
    docker login -u "$QUAY_STACKROX_IO_RW_USERNAME" --password-stdin <<<"$QUAY_STACKROX_IO_RW_PASSWORD" quay.io
    _tag_image_set "quay.io/stackrox-io" "$tag"
    _push_image_set "quay.io/stackrox-io" "$tag"
}

poll_for_system_test_images() {
    info "Polling for images required for system tests"

    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: poll_for_system_test_images <seconds to wait>"
    fi

    local time_limit="$1"

    require_environment "QUAY_RHACS_ENG_BEARER_TOKEN"

    local tag
    tag="$(make --quiet tag)"
    local start_time
    start_time="$(date '+%s')"

    _image_exists() {
        local name="$1"
        local url="https://quay.io/api/v1/repository/rhacs-eng/$name/tag?specificTag=$tag"
        info "Checking for $name using $url"
        local check
        check=$(curl --location -sS -H "Authorization: Bearer ${QUAY_RHACS_ENG_BEARER_TOKEN}" "$url")
        echo "$check"
        [[ "$(jq -r '.tags | first | .name' <<<"$check")" == "$tag" ]]
    }

    while true; do
        ### MODIFIED - Replaced with Scanner-related images
        if _image_exists "scanner" && _image_exists "scanner-db" && _image_exists "scanner-slim" && _image_exists "scanner-db-slim"; then
            info "All images exist"
            break
        fi
        if (( $(date '+%s') - start_time > time_limit )); then
           die "Timed out waiting for images after ${time_limit} seconds"
        fi
        sleep 60
    done
}

is_tagged() {
    local tags
    tags="$(git tag --contains)"
    [[ -n "$tags" ]]
}

is_nightly_run() {
    [[ "${CIRCLE_TAG:-}" =~ -nightly- ]]
}

is_in_PR_context() {
    if is_CIRCLECI && [[ -n "${CIRCLE_PULL_REQUEST:-}" ]]; then
        return 0
    elif is_OPENSHIFT_CI && [[ -n "${PULL_NUMBER:-}" ]]; then
        return 0
    elif is_OPENSHIFT_CI && [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
        # bin, test-bin, images
        local pull_request
        pull_request=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].number' 2>&1) || return 1
        [[ "$pull_request" =~ ^[0-9]+$ ]] && return 0
    fi

    return 1
}

is_openshift_CI_rehearse_PR() {
    [[ "$(get_repo_full_name)" == "openshift/release" ]]
}

get_base_ref() {
    if is_CIRCLECI; then
        echo "${CIRCLE_BRANCH}"
    elif is_OPENSHIFT_CI; then
        if [[ -n "${PULL_BASE_REF:-}" ]]; then
            # presubmit, postsubmit and batch runs
            # (ref: https://github.com/kubernetes/test-infra/blob/master/prow/jobs.md#job-environment-variables)
            echo "${PULL_BASE_REF}"
        elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
            # periodics - CLONEREFS_OPTIONS exists in binary_build_commands and images.
            local base_ref
            base_ref="$(jq -r <<<"${CLONEREFS_OPTIONS}" '.refs[0].base_ref')" || die "invalid CLONEREFS_OPTIONS yaml"
            if [[ "$base_ref" == "null" ]]; then
                die "expect: base_ref in CLONEREFS_OPTIONS.refs[0]"
            fi
            echo "${base_ref}"
        else
            die "Expect PULL_BASE_REF or CLONEREFS_OPTIONS"
        fi
    else
        die "unsupported"
    fi
}

get_repo_full_name() {
    if is_CIRCLECI; then
        ### MODIFIED: stackrox/stackrox -> stackrox/scanner
        # CIRCLE_REPOSITORY_URL=git@github.com:stackrox/scanner.git
        echo "${CIRCLE_REPOSITORY_URL:15:-4}"
    elif is_OPENSHIFT_CI; then
        if [[ -n "${REPO_OWNER:-}" ]]; then
            # presubmit, postsubmit and batch runs
            # (ref: https://github.com/kubernetes/test-infra/blob/master/prow/jobs.md#job-environment-variables)
            [[ -n "${REPO_NAME:-}" ]] || die "expect: REPO_NAME"
            echo "${REPO_OWNER}/${REPO_NAME}"
        elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
            # periodics - CLONEREFS_OPTIONS exists in binary_build_commands and images.
            local org
            local repo
            org="$(jq -r <<<"${CLONEREFS_OPTIONS}" '.refs[0].org')" || die "invalid CLONEREFS_OPTIONS yaml"
            repo="$(jq -r <<<"${CLONEREFS_OPTIONS}" '.refs[0].repo')" || die "invalid CLONEREFS_OPTIONS yaml"
            if [[ "$org" == "null" ]] || [[ "$repo" == "null" ]]; then
                die "expect: org and repo in CLONEREFS_OPTIONS.refs[0]"
            fi
            echo "${org}/${repo}"
        else
            die "Expect REPO_OWNER/NAME or CLONEREFS_OPTIONS"
        fi
    else
        die "unsupported"
    fi
}

pr_has_label() {
    if [[ -z "${1:-}" ]]; then
        die "usage: pr_has_label <expected label> [<pr details>]"
    fi

    local expected_label="$1"
    local pr_details
    local exitstatus=0
    pr_details="${2:-$(get_pr_details)}" || exitstatus="$?"
    if [[ "$exitstatus" != "0" ]]; then
        info "Warning: checking for a label in a non PR context"
        false
    fi
    jq '([.labels | .[].name]  // []) | .[]' -r <<<"$pr_details" | grep -qx "${expected_label}"
}

# get_pr_details() from GitHub and display the result. Exits 1 if not run in CI in a PR context.
_PR_DETAILS=""
get_pr_details() {
    local pull_request
    local org
    local repo

    if [[ -n "${_PR_DETAILS}" ]]; then
        echo "${_PR_DETAILS}"
        return
    fi

    _not_a_PR() {
        echo '{ "msg": "this is not a PR" }'
        exit 1
    }

    if is_CIRCLECI; then
        [ -n "${CIRCLE_PULL_REQUEST:-}" ] || _not_a_PR
        [ -n "${CIRCLE_PROJECT_USERNAME}" ] || { echo "CIRCLE_PROJECT_USERNAME not found" ; exit 2; }
        [ -n "${CIRCLE_PROJECT_REPONAME}" ] || { echo "CIRCLE_PROJECT_REPONAME not found" ; exit 2; }
        pull_request="${CIRCLE_PULL_REQUEST##*/}"
        org="${CIRCLE_PROJECT_USERNAME}"
        repo="${CIRCLE_PROJECT_REPONAME}"
    elif is_OPENSHIFT_CI; then
        if [[ -n "${JOB_SPEC:-}" ]]; then
            pull_request=$(jq -r <<<"$JOB_SPEC" '.refs.pulls[0].number')
            org=$(jq -r <<<"$JOB_SPEC" '.refs.org')
            repo=$(jq -r <<<"$JOB_SPEC" '.refs.repo')
        elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
            pull_request=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].number')
            org=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].org')
            repo=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].repo')
        else
            echo "Expect a JOB_SPEC or CLONEREFS_OPTIONS"
            exit 2
        fi
        [[ "${pull_request}" == "null" ]] && _not_a_PR
    else
        echo "Expect Circle or OpenShift CI"
        exit 2
    fi

    headers=()
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        headers+=(-H "Authorization: token ${GITHUB_TOKEN}")
    fi

    url="https://api.github.com/repos/${org}/${repo}/pulls/${pull_request}"
    pr_details=$(curl --retry 5 -sS "${headers[@]}" "${url}")
    if [[ "$(jq .id <<<"$pr_details")" == "null" ]]; then
        # A valid PR response is expected at this point
        echo "Invalid response from GitHub: $pr_details"
        exit 2
    fi
    _PR_DETAILS="$pr_details"
    echo "$pr_details"
}

GATE_JOBS_CONFIG="$SCRIPTS_ROOT/scripts/ci/gate-jobs-config.json"

gate_job() {
    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: gate_job <job>"
    fi

    local job="$1"
    local job_config
    job_config="$(jq -r .\""$job"\" "$GATE_JOBS_CONFIG")"

    info "Will determine whether to run: $job"

    # TODO(RS-509) remove once this behaves better
    if [[ "$job_config" == "null" ]]; then
        info "$job will run because there is no gating criteria for $job"
        return
    fi

    local pr_details
    local exitstatus=0
    pr_details="$(get_pr_details)" || exitstatus="$?"

    if [[ "$exitstatus" == "0" ]]; then
        if is_openshift_CI_rehearse_PR; then
            gate_openshift_release_rehearse_job "$job" "$pr_details"
        else
            gate_pr_job "$job_config" "$pr_details"
        fi
    elif [[ "$exitstatus" == "1" ]]; then
        gate_merge_job "$job_config"
    else
        die "Could not determine if this is a PR versus a merge"
    fi
}

get_var_from_job_config() {
    local var_name="$1"
    local job_config="$2"

    local value
    value="$(jq -r ."$var_name" <<<"$job_config")"
    if [[ "$value" == "null" ]]; then
        die "$var_name is not defined in this jobs config"
    fi
    if [[ "${value:0:1}" == "[" ]]; then
        value="$(jq -cr '.[]' <<<"$value")"
    fi
    echo "$value"
}

gate_pr_job() {
    local job_config="$1"
    local pr_details="$2"

    local run_with_labels=()
    local skip_with_label
    local run_with_changed_path
    local changed_path_to_ignore
    local run_with_labels_from_json
    run_with_labels_from_json="$(get_var_from_job_config run_with_labels "$job_config")"
    if [[ -n "${run_with_labels_from_json}" ]]; then
        mapfile -t run_with_labels <<<"${run_with_labels_from_json}"
    fi
    skip_with_label="$(get_var_from_job_config skip_with_label "$job_config")"
    run_with_changed_path="$(get_var_from_job_config run_with_changed_path "$job_config")"
    changed_path_to_ignore="$(get_var_from_job_config changed_path_to_ignore "$job_config")"

    if [[ -n "$skip_with_label" ]]; then
        if pr_has_label "${skip_with_label}" "${pr_details}"; then
            info "$job will not run because the PR has label $skip_with_label"
            exit 0
        fi
    fi

    for run_with_label in "${run_with_labels[@]}"; do
        if pr_has_label "${run_with_label}" "${pr_details}"; then
            info "$job will run because the PR has label $run_with_label"
            return
        fi
    done

    if [[ -n "${run_with_changed_path}" || -n "${changed_path_to_ignore}" ]]; then
        local diff_base
        if is_CIRCLECI; then
            diff_base="$(git merge-base HEAD origin/master)"
            echo "Determined diff-base as ${diff_base}"
            echo "Master SHA: $(git rev-parse origin/master)"
        elif is_OPENSHIFT_CI; then
            diff_base="$(jq -r '.refs[0].base_sha' <<<"$CLONEREFS_OPTIONS")"
            echo "Determined diff-base as ${diff_base}"
            [[ "${diff_base}" != "null" ]] || die "Could not find base_sha in CLONEREFS_OPTIONS: $CLONEREFS_OPTIONS"
        else
            die "unsupported"
        fi
        echo "Diffbase diff:"
        { git diff --name-only "${diff_base}" | cat ; } || true
        # TODO(RS-509) remove once this behaves better
        ignored_regex="${changed_path_to_ignore}"
        [[ -n "$ignored_regex" ]] || ignored_regex='$^' # regex that matches nothing
        match_regex="${run_with_changed_path}"
        [[ -n "$match_regex" ]] || match_regex='^.*$' # grep -E -q '' returns 0 even on empty input, so we have to specify some pattern
        if grep -E -q "$match_regex" < <({ git diff --name-only "${diff_base}" || echo "???" ; } | grep -E -v "$ignored_regex"); then
            info "$job will run because paths matching $match_regex (and not matching ${ignored_regex}) had changed."
            return
        fi
    fi

    info "$job will be skipped"
    exit 0
}

gate_merge_job() {
    local job_config="$1"

    local run_on_master
    local run_on_tags
    run_on_master="$(get_var_from_job_config run_on_master "$job_config")"
    run_on_tags="$(get_var_from_job_config run_on_tags "$job_config")"

    local base_ref
    base_ref="$(get_base_ref)" || {
        info "Warning: error running get_base_ref():"
        echo "${base_ref}"
        info "will continue with tests."
    }

    if [[ "${base_ref}" == "master" && "${run_on_master}" == "true" ]]; then
        info "$job will run because this is master and run_on_master==true"
        return
    fi

    if is_tagged && [[ "${run_on_tags}" == "true" ]]; then
        info "$job will run because the head of this branch is tagged and run_on_tags==true"
        return
    fi

    info "$job will be skipped - neither master/run_on_master or tagged/run_on_tags"
    exit 0
}

# gate_openshift_release_rehearse_job() - use the PR description to indicate if
# the pj-rehearse job should run for configured jobs.
gate_openshift_release_rehearse_job() {
    local job="$1"
    local pr_details="$2"

    if [[ "$(jq -r '.body' <<<"$pr_details")" =~ open.the.gate.*$job ]]; then
        info "$job will run because the gate was opened"
        return
    fi

    cat << _EOH_
$job will be skipped. If you want to run a gated job during openshift/release pj-rehearsal
update the PR description with:
open the gate: $job
_EOH_
    exit 0
}

openshift_ci_mods() {
    info "BEGIN OpenShift CI mods"

    info "Env A-Z dump:"
    env | sort | grep -E '^[A-Z]' || true

    info "Git log:"
    git log --oneline --decorate -n 20 || true

    info "Recent git refs:"
    git for-each-ref --format='%(creatordate) %(refname)' --sort=creatordate | tail -20

    info "Current Status:"
    "$ROOT/status.sh" || true

    # For ci_export(), override BASH_ENV from stackrox-test with something that is writable.
    BASH_ENV=$(mktemp)
    export BASH_ENV

    # These are not set in the binary_build_commands or image build envs.
    export CI=true
    export OPENSHIFT_CI=true

    if is_in_PR_context && ! is_openshift_CI_rehearse_PR; then
        local sha
        sha=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].sha') || echo "WARNING: Cannot find pull sha"
        if [[ -n "${sha:-}" ]] && [[ "$sha" != "null" ]]; then
            info "Will checkout SHA to match PR: $sha"
            git checkout "$sha"
        else
            echo "WARNING: Could not determine a SHA for this PR, ${sha:-}"
        fi
    fi

    # Provide Circle CI vars that are commonly used
    export CIRCLE_JOB="${JOB_NAME:-${OPENSHIFT_BUILD_NAME}}"
    CIRCLE_TAG="$(git tag --sort=creatordate --contains | tail -1)" || echo "Warning: Cannot get tag"
    export CIRCLE_TAG

    handle_nightly_runs

    info "Status after mods:"
    "$ROOT/status.sh" || true

    info "END OpenShift CI mods"
}

openshift_ci_import_creds() {
    shopt -s nullglob
    for cred in /tmp/secret/**/[A-Z]*; do
        export "$(basename "$cred")"="$(cat "$cred")"
    done
}

openshift_ci_e2e_mods() {
    # NAMESPACE is injected by OpenShift CI for the cluster that is running the
    # tests but this can have side effects for scanner tests due to its use as
    # the default namespace e.g. with helm.
    if [[ -n "${NAMESPACE:-}" ]]; then
        export OPENSHIFT_CI_NAMESPACE="$NAMESPACE"
        unset NAMESPACE
    fi

    # Similarly the incoming KUBECONFIG is best avoided.
    if [[ -n "${KUBECONFIG:-}" ]]; then
        info "There is an incoming KUBECONFIG in ${KUBECONFIG}"
        export OPENSHIFT_CI_KUBECONFIG="$KUBECONFIG"
    fi
    KUBECONFIG="$(mktemp)"
    info "KUBECONFIG set: ${KUBECONFIG}"
    export KUBECONFIG

    # KUBERNETES_{PORT,SERVICE} env values also interact with commandline kubectl tests
    if env | grep -e ^KUBERNETES_; then
        local envfile
        envfile="$(mktemp)"
        info "Will clear ^KUBERNETES_ env"
        env | grep -e ^KUBERNETES_ | cut -d= -f1 | awk '{ print "unset", $1 }' > "$envfile"
        # shellcheck disable=SC1090
        source "$envfile"
    fi
}

handle_nightly_runs() {
    if ! is_OPENSHIFT_CI; then
        die "Only for OpenShift CI"
    fi

    if ! is_in_PR_context; then
        info "Debug:"
        echo "JOB_NAME: ${JOB_NAME:-}"
        echo "JOB_NAME_SAFE: ${JOB_NAME_SAFE:-}"
    fi

    local nightly_tag_prefix
    nightly_tag_prefix="$(git describe --tags --abbrev=0 --exclude '*-nightly-*')-nightly-"
    if ! is_in_PR_context && [[ "${JOB_NAME_SAFE:-}" =~ ^nightly- ]]; then
        ci_export CIRCLE_TAG "${nightly_tag_prefix}$(date '+%Y%m%d')"
    elif is_in_PR_context && pr_has_label "simulate-nightly-run"; then
        local sha
        if [[ -n "${PULL_PULL_SHA:-}" ]]; then
            sha="${PULL_PULL_SHA}"
        else
            sha=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].sha') || die "Cannot find pull sha"
            [[ "$sha" != "null" ]] || die "Cannot find pull sha"
        fi
        ci_export CIRCLE_TAG "${nightly_tag_prefix}${sha:0:8}"
    fi
}

store_test_results() {
    if [[ "$#" -ne 2 ]]; then
        die "missing args. usage: store_test_results <from> <to>"
    fi

    if ! is_OPENSHIFT_CI; then
        return
    fi

    local from="$1"
    local to="$2"

    info "Copying test results from $from to $to"

    local dest="${ARTIFACT_DIR}/$to"

    cp -a "$from" "$dest" || true # (best effort)
}

send_slack_notice_for_failures_on_merge() {
    local exitstatus="${1:-}"

    if ! is_OPENSHIFT_CI || [[ "$exitstatus" == "0" ]] || is_in_PR_context || is_nightly_run; then
        return 0
    fi

    local tag
    tag="$(make --quiet tag)"
    if [[ "$tag" =~ $RELEASE_RC_TAG_BASH_REGEX ]]; then
        return 0
    fi

    local webhook_url="${TEST_FAILURES_NOTIFY_WEBHOOK}"

    local commit_details
    org=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].org') || return 1
    repo=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].repo') || return 1
    [[ "$org" != "null" ]] && [[ "$repo" != "null" ]] || return 1
    local commit_details_url="https://api.github.com/repos/${org}/${repo}/commits/${OPENSHIFT_BUILD_COMMIT}"
    commit_details=$(curl --retry 5 -sS "${commit_details_url}") || return 1

    local job_name="${JOB_NAME_SAFE#merge-}"

    local commit_msg
    commit_msg=$(jq -r <<<"$commit_details" '.commit.message') || return 1
    commit_msg="${commit_msg%%$'\n'*}" # use first line of commit msg
    local commit_url
    commit_url=$(jq -r <<<"$commit_details" '.html_url') || return 1
    local author
    author=$(jq -r <<<"$commit_details" '.commit.author.name') || return 1
    [[ "$commit_msg" != "null" ]] && [[ "$commit_url" != "null" ]] && [[ "$author" != "null" ]] || return 1

    local log_url="https://prow.ci.openshift.org/view/gs/origin-ci-test/logs/${JOB_NAME}/${BUILD_ID}"

    # shellcheck disable=SC2016
    local body='
{
    "text": "*Job Name:* \($job_name)",
    "blocks": [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "Prow job failure: \($job_name)"
			}
		},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Commit:* <\($commit_url)|\($commit_msg)>\n*Repo:* \($repo)\n*Author:* \($author)\n*Log:* \($log_url)"
            }
        },
		{
			"type": "divider"
		}
    ]
}
'

    echo "About to post:"
    jq --null-input --arg job_name "$job_name" --arg commit_url "$commit_url" --arg commit_msg "$commit_msg" \
       --arg repo "$repo" --arg author "$author" --arg log_url "$log_url" "$body"

    jq --null-input --arg job_name "$job_name" --arg commit_url "$commit_url" --arg commit_msg "$commit_msg" \
       --arg repo "$repo" --arg author "$author" --arg log_url "$log_url" "$body" | \
    curl -XPOST -d @- -H 'Content-Type: application/json' "$webhook_url"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
