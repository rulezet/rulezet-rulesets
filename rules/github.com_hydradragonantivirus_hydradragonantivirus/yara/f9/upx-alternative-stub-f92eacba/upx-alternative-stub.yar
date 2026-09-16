import "pe"
rule _UPX_Alternative_stub_
{
	meta:
		description = "UPX Alternative stub"
	strings:
		$0 = {50 BE 8D BE 57 83}
	condition:
		$0 at pe.entry_point
}