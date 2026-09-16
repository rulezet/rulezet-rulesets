rule SuicideScriptR
{
		meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		
	condition:
		all of them

}