rule php_reverse_shell_2 {
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
		id = "f10cc33e-0cb6-5d08-af1f-5ef76368de9d"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii 
		$s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii 
	condition:
		filesize < 10KB and all of them
}