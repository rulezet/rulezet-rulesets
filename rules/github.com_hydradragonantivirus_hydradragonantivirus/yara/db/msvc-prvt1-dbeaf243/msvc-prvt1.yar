rule msvc_prvt1
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ Private Version 1"
		group = "15"
		function = "0"
	strings:
		$a0 = { 8B 44 24 08 83 ?? ?? 74 }
	condition:
		$a0
}