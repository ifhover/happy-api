package kiro

func ensureAlternatingHistory(history []map[string]any) []map[string]any {
	if len(history) <= 1 {
		return history
	}

	fixed := []map[string]any{history[0]}
	for i := 1; i < len(history); i++ {
		prev := fixed[len(fixed)-1]
		cur := history[i]

		_, prevUser := prev["userInputMessage"]
		_, curUser := cur["userInputMessage"]
		_, prevAssistant := prev["assistantResponseMessage"]
		_, curAssistant := cur["assistantResponseMessage"]

		if prevUser && curUser {
			fixed = append(fixed, map[string]any{
				"assistantResponseMessage": map[string]any{"content": "Continue"},
			})
		} else if prevAssistant && curAssistant {
			fixed = append(fixed, map[string]any{
				"userInputMessage": map[string]any{
					"content": "Continue",
					"modelId": "claude-sonnet-4.6",
					"origin":  "AI_EDITOR",
				},
			})
		}

		fixed = append(fixed, cur)
	}

	return fixed
}
