rule firewallOpener
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
	 $ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
	 
	condition:
		any of them
		
}