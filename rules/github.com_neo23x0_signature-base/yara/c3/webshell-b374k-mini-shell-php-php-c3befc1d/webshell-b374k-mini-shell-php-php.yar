rule WebShell_b374k_mini_shell_php_php {
	meta:
		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"
		id = "d5b0dfa5-46b5-5323-a8e8-b119d8c2c8e5"
	strings:
		$s0 = "@error_reporting(0);" fullword
		$s2 = "@eval(gzinflate(base64_decode($code)));" fullword
		$s3 = "@set_time_limit(0); " fullword
	condition:
		all of them
}