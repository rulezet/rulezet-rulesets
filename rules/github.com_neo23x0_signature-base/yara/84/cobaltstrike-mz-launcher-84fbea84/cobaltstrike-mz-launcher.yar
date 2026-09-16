rule CobaltStrike_MZ_Launcher {
	meta:
		description = "Detects CobaltStrike MZ header ReflectiveLoader launcher"
		author = "yara@s3c.za.net"
		date = "2021-07-08"
		id = "461a4741-11c5-53d9-b8e1-52d64cfe755b"
    strings:
        $mz_launcher = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D }
	condition:
		$mz_launcher
}