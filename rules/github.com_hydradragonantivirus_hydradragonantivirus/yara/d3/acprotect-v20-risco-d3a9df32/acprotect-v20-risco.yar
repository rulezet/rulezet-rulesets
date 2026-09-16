import "pe"
rule _ACProtect_V20__risco_
{
	meta:
		description = "ACProtect V2.0 -> risco"
	strings:
		$0 = {68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C3 C3}
	condition:
		$0 at pe.entry_point
}