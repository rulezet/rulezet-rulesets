rule Mithril_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
	strings:
		$s0 = "please enter the password:"
		$s3 = "\\dllTest.pdb"
	condition:
		all of them
}