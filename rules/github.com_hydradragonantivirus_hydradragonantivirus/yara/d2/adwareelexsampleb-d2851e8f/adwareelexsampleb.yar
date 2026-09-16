rule AdwareELEXSampleB
{
	meta:
		Description  = "Adware.ELEX.B.vb"
		ThreatLevel  = "5"

	strings:

		$pdb = "Release\\SFKEX.pdb" ascii wide
		$ = "21e223b3f0c97db3c281da1g7zccaefozzjcktmlma" ascii wide
		$ = "http://xa.xingcloud.com/v4/sof-everything" ascii wide
		$ = "http://www.mysearch123.com" ascii wide
		$ = "SFKEX.exe" ascii wide
		$ = "SFKEX.dll" ascii wide
		$ = "SFKURL" ascii wide

	condition:
		2 of them
}