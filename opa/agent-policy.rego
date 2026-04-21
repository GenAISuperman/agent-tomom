package agent.policy

deny[msg] {
	not input.agent.id
	msg := "agent.id is required"
}

deny[msg] {
	contains(input.agent.id, "{{")
	msg := "agent.id still contains placeholder"
}

deny[msg] {
	not input.agent.team
	msg := "agent.team is required"
}

deny[msg] {
	contains(input.agent.team, "{{")
	msg := "agent.team still contains placeholder"
}

deny[msg] {
	not input.identity.sp_client_id
	msg := "identity.sp_client_id is required"
}

deny[msg] {
	contains(input.identity.sp_client_id, "{{")
	msg := "identity.sp_client_id still contains placeholder"
}

deny[msg] {
	not input.identity.keyvault_url
	msg := "identity.keyvault_url is required"
}

deny[msg] {
	contains(input.identity.keyvault_url, "{{")
	msg := "identity.keyvault_url still contains placeholder"
}

deny[msg] {
	not input.evaluation.ci_gate == true
	msg := "evaluation.ci_gate must be true"
}

deny[msg] {
	input.evaluation.pass_threshold < 0.95
	msg := "evaluation.pass_threshold must be >= 0.95"
}

deny[msg] {
	not input.prompts.active_version
	msg := "prompts.active_version is required"
}

deny[msg] {
	not input.prompts.source
	msg := "prompts.source is required"
}
