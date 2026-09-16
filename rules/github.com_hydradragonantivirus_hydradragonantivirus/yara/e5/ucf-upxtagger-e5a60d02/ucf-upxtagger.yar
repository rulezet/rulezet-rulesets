rule ucf_upxtagger
{
	meta:
		author = "PEiD"
		description = "uCF UPX-tagger -> ZigD/uCF"
		group = "444"
		function = "0"
	strings:
		$a0 = { EB 01 E8 ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC }
	condition:
		$a0
}