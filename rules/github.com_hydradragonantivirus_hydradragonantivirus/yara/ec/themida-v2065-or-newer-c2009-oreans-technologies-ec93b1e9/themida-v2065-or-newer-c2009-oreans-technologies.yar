import "pe"
rule _Themida_v2065_or_newer__c2009_Oreans_Technologies_
{
	meta:
		description = "Themida v2.0.6.5 (or newer) -> (c)2009 Oreans Technologies"
	strings:
		$0 = {52 BA 64 00 00 00 EB 1B B9 00 10 00 00 EB 05 03 C1 03 C3 49 0B C9 75 F7 52 54 54 FF 15}
	condition:
		$0 at pe.entry_point
}