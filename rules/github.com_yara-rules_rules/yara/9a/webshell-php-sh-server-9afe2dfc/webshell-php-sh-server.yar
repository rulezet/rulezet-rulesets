rule webshell_php_sh_server : webshell {
	meta:
		description = "Web Shell - file server.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "d87b019e74064aa90e2bb143e5e16cfa"
	strings:
		$s0 = "eval(getenv('HTTP_CODE'));" fullword
	condition:
		all of them
}