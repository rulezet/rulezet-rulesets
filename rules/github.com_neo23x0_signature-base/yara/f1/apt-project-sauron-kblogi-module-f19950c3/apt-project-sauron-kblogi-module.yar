rule APT_Project_Sauron_kblogi_module {
	meta:
		description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		id = "e1dd4d1a-1089-5897-8f4a-52c7068802fa"
	strings:
		$x1 = "Inject using process name or pid. Default"
		$s2 = "Convert mode: Read log from file and convert to text"
		$s3 = "Maximum running time in seconds"
	condition:
		$x1 or 2 of them
}