# Agent workflow (chief-of-staff)

Agreed with the owner on 2026-11-27. Applies to every open sub-issue of #1, in dependency order (#3 → #4 → #5 → #6 → #7 → #9).

1. Spawn a **fresh implementor subagent** per issue: branch `feat/<slug>` from `master`, implement the issue's acceptance criteria, run `uv sync` + `uv run pytest` green, commit (signing is on), push branch. **No PR yet.**
2. Spawn a **fresh reviewer subagent** per issue: review the branch against the issue's acceptance criteria (run the tests), verdict APPROVE or a list of required changes.
3. On APPROVE: open the PR. If CI passes, merge to `master`, delete the feature branch (local + remote), close out the issue.
4. On reviewer rejection or CI failure: send the feedback to the **same** implementor (same issue = same subagent) to fix; repeat from step 2.
5. Next issue starts with a new implementor + new reviewer.

Environment notes for agents: docker is unavailable in this sandbox (validate compose YAML with PyYAML); uv + gh are available; repo at /home/daniel/Documents/projects/hermod-monitor; read AGENTS.md + docs/agents/* + docs/wiki/* first. Public-repo rule applies: no secrets anywhere (docs/wiki/public-repo-rule.md).
