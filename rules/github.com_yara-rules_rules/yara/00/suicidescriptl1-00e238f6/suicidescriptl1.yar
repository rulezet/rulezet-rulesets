rule SuicideScriptL1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = ":L1\ndel \"%s\"\nif exist \"%s\" goto L1\ndel \"%s\"\n"
	condition:
		any of them
}