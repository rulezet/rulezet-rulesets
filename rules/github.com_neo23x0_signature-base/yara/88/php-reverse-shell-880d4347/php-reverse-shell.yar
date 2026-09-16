rule php_reverse_shell {
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
		id = "306d150f-95a8-57fd-8f5e-786c429af6b3"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii 
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii 
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii 
	condition:
		filesize < 15KB and all of them
}