rule IndiaCharlie_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "WMPNetworkSvcUpdate"
		$ = "backSched.dll"
		$ = "\\mspaint.exe"
		$aesKey = "X,LLIe{))%%l2i<[AM|aq!Ql/lPlw]d7@C-#j.<c|#*}Kx4_H(q^F-F^p/[t#%HT"
	condition:
		2 of them or $aesKey
}