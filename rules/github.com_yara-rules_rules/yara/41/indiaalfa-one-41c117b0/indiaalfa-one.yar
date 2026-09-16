rule IndiaAlfa_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "HwpFilePathCheck.dll"
		$ = "AdobeArm.exe"
		$ = "OpenDocument"
		
	condition:
		2 of them

}