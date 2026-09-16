import "pe"
rule _Warning_may_be_RCryptor_by_Vaska_unknown_ver__21032006_2317_
{
	meta:
		description = "Warning! may be RCryptor by Vaska unknown ver  (21.03.2006 23:17)"
	strings:
		$0 = {EB F3 E8 00 00 00 00 C3}
	condition:
		$0 at pe.entry_point
}