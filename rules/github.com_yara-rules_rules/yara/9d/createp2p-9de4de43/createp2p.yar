rule createP2P
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "CreatP2P Thread" wide

	condition:
		any of them
}