rule Mithril_v1_45_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
	strings:
		$s3 = "syspath"
		$s4 = "\\Mithril"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}