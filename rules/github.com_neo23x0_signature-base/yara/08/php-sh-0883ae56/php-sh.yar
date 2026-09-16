rule PHP_sh {
	meta:
		description = "Webshells Auto-generated - file sh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
		id = "08dff4db-3b1c-5702-a8c9-efaedf83c4ff"
	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
	condition:
		all of them
}