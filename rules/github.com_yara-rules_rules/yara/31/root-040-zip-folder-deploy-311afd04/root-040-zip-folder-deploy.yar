rule _root_040_zip_Folder_deploy {
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}