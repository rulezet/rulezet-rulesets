rule uploader {
	meta:
		description = "Webshells Auto-generated - file uploader.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b9a9aab319964351b46bd5fc9d6246a8"
	strings:
		$s0 = "move_uploaded_file($userfile, \"entrika.php\"); "
	condition:
		all of them
}