import "pe"
rule _setupexe_Section34data_
{
	meta:
		description = "setup.exe Section(3/4,.data)"
	strings:
		$0 = {80 16 42 00 48 05 44 00 00 00 00 00 2E 3F 41 56 5F 63 6F 6D 5F 65 72}
	condition:
		$0 at pe.entry_point
}