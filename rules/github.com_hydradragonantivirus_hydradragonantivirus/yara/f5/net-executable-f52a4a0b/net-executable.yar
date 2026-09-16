import "pe"
rule _NET_executable_
{
	meta:
		description = ".NET executable"
	strings:
		$0 = {FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10}
		$1 = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}