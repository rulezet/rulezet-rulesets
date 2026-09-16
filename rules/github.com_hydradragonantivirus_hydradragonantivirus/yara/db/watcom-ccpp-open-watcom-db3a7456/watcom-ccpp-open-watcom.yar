import "pe"
rule _WATCOM_CCpp__Open_Watcom_
{
	meta:
		description = "WATCOM C/C++ -> Open Watcom"
	strings:
		$0 = {E9 ?? ?? ?? 00 ?? ?? ?? 00 57 41}
	condition:
		$0 at pe.entry_point
}