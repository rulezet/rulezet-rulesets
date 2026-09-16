rule IndiaBravo_PapaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "pmsconfig.msi" wide
		$ = "scvrit001.bat"
	condition:
		all of them
}