import "pe"
rule _CodeLock_vxx_
{
	meta:
		description = "Code-Lock vx.x"
	strings:
		$0 = {83 EC 10 53 56 57 E8 C4}
	condition:
		$0 at pe.entry_point
}