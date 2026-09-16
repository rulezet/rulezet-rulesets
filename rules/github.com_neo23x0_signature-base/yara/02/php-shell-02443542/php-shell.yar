rule php_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		id = "8d3dcb16-090b-5a9f-b3d2-3822ec467f69"
	strings:
		$s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii 
		$s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii 
		$s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii 
		$s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii 
	condition:
		filesize < 40KB and all of them
}