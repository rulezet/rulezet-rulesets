rule SuicideScriptR1_Multi
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
	
	strings:
		$ = "\" goto R1\ndel /a \""
		$ = "\"\nif exist \""
		$ = "@echo off\n:R1\ndel /a \""
	condition:
		all of them
}