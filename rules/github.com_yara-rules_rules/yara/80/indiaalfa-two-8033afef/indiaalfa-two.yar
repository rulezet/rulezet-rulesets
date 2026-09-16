rule IndiaAlfa_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "ExePath: %s\nXlsPath: %s\nTmpPath: %s\n"
		
	condition:
		any of them

}