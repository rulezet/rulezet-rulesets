rule Unpack_Injectt {
	meta:
		description = "Webshells Auto-generated - file Injectt.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8a5d2158a566c87edc999771e12d42c5"
		id = "80dc3086-41a6-5e30-bbf4-463500fe5e33"
	strings:
		$s2 = "%s -Run                              -->To Install And Run The Service"
		$s3 = "%s -Uninstall                        -->To Uninstall The Service"
		$s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
	condition:
		all of them
}