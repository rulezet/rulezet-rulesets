rule PHP_Cloaked_Webshell_SuperFetchExec {
	meta:
		description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
		reference = "http://goo.gl/xFvioC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		id = "4611129a-9865-5603-b1ec-7db0058a80d7"
	strings:
		$s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
	condition:
		$s0
}