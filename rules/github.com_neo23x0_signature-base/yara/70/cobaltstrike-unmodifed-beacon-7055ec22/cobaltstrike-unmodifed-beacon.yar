rule CobaltStrike_Unmodifed_Beacon {
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
		id = "8eeb03f9-9698-5a46-b45b-224d5c3f3df7"
	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"
	condition:
		all of them
}