rule _root_040_zip_Folder_deploy {
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
		id = "7e592ab2-8a53-59d5-a45d-971398586479"
	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}