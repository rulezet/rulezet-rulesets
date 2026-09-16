rule armd350b1
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.50b1 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 F3 D8 04 24 9C 51 33 C9 75 02 F3 D8 04 24 EB 1A EB 33 C9 75 18 59 F3 D8 04 24 7A 0C 70 0E EB 0D E8 72 0E 79 EE }
	condition:
		$a0
}