import "pe"
rule _kryptor_3_
{
	meta:
		description = "kryptor 3"
	strings:
		$0 = {E8 03 E9 EB 6C 58 40 FF}
	condition:
		$0 at pe.entry_point
}