rule RansomSampleTeslaCryptB
{
	meta:
		Description  = "Ransom.TeslaCrypt.B.sm"
		ThreatLevel  = "5"

	strings:
		$ = "help_recover_instructions" ascii wide nocase
		$ = "help_recover_instructions.TXT" ascii wide nocase
		$ = "help_recover_instructions.png" ascii wide nocase
	condition:
		any of them
}