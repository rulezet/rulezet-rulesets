rule Antichat_Socks5_Server_php_php {
	meta:
		description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "cbe9eafbc4d86842a61a54d98e5b61f1"
		id = "35d0930c-ef07-5fd4-9d7a-c0d685f92339"
	strings:
		$s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
		$s3 = "#   [+] Domain name address type"
		$s4 = "www.antichat.ru"
	condition:
		1 of them
}