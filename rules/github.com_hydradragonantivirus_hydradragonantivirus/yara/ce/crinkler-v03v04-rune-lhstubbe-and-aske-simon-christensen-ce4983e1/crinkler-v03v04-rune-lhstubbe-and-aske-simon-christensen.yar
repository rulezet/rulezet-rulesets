import "pe"
rule _Crinkler_V03V04__Rune_LHStubbe_and_Aske_Simon_Christensen_
{
	meta:
		description = "Crinkler V0.3-V0.4 -> Rune L.H.Stubbe and Aske Simon Christensen"
	strings:
		$0 = {B8 00 00 42 00 31 DB 43 EB 58}
	condition:
		$0 at pe.entry_point
}