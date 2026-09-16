import "pe"
rule _muckis_protector_I__mucki_
{
	meta:
		description = "mucki's protector I -> mucki"
	strings:
		$0 = {BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9}
	condition:
		$0 at pe.entry_point
}