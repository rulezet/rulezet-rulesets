rule PHP_sh {
	meta:
		description = "Webshells Auto-generated - file sh.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
	condition:
		all of them
}