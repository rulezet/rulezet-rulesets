rule RansomSampleChimeraB
{
	meta:
		Description  = "Ransom.Win32.Chimera.sm"
		ThreatLevel  = "5"

	strings:
		$ = "YOUR_FILES_ARE_ENCRYPTED.HTML" ascii wide nocase
		$ = "Projects\\Ransom\\bin\\Release\\Core.pdb" ascii wide nocase
		$ = "BM-2cW44Yq9DWbHYnRSfzBLVxvE6WjadchNBt" ascii wide nocase
	condition:
		any of them
}