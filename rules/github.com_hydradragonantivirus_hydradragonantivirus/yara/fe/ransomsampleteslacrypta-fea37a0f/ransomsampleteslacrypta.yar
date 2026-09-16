rule RansomSampleTeslaCryptA
{
	meta:
		Description  = "Ransom.TeslaCrypt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "HOWTO_RESTORE_FILES.TXT" ascii wide nocase
		$ = "HOWTO_RESTORE_FILES.bmp" ascii wide nocase
		$ = "HOWTO_RESTORE_FILES.HTML" ascii wide nocase
	condition:
		any of them
}