rule RansomSampleHydraCrypt
{
	meta:
		Description  = "Ransom.Win32.HydraCrypt.sm"
		ThreatLevel  = "5"

	strings:
		$ = "README_DECRYPT_HYDRA_ID_" ascii wide nocase
		$ = "hydracrypt_ID_" ascii wide nocase
		$ = "HYDRACRYPT" ascii wide nocase
		$ = "ccc=hydra01_" ascii wide nocase
	condition:
		2 of them
}