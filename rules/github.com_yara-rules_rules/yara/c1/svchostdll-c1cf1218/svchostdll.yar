rule svchostdll {
	meta:
		description = "Webshells Auto-generated - file svchostdll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f6756c8cb0b454c452055f189e4c3f4"
	strings:
		$s0 = "InstallService"
		$s1 = "RundllInstallA"
		$s2 = "UninstallService"
		$s3 = "&G3 Users In RegistryD"
		$s4 = "OL_SHUTDOWN;I"
		$s5 = "SvcHostDLL.dll"
		$s6 = "RundllUninstallA"
		$s7 = "InternetOpenA"
		$s8 = "Check Cloneomplete"
	condition:
		all of them
}