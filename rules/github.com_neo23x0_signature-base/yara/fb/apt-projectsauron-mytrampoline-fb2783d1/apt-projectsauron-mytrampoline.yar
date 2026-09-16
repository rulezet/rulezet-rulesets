rule apt_ProjectSauron_MyTrampoline  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron MyTrampoline module"
	version = "1.0"
	reference = "https://securelist.com/blog/"
	id = "b4f2cabf-11da-5fa1-8c23-0a177f8a4741"
strings:
	$a1 = ":\\System Volume Information\\{" wide
	$a2 = "\\\\.\\PhysicalDrive%d" wide
	$a3 = "DMWndClassX%d"

	$b1 = "{774476DF-C00F-4e3a-BF4A-6D8618CFA532}" ascii wide
	$b2 = "{820C02A4-578A-4750-A409-62C98F5E9237}" ascii wide
condition:
	uint16(0) == 0x5A4D and
	filesize < 5000000 and
	(all of ($a*) or any of ($b*))
}