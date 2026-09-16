import "pe"
rule _UPX_v0896__v102__v105__v122_Delphi_stub_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 (Delphi) stub"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77}
	condition:
		$0 at pe.entry_point
}