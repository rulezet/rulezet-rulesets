rule saphpshell {
	meta:
		description = "Webshells Auto-generated - file saphpshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d7bba8def713512ddda14baf9cd6889a"
		id = "42bcd739-714e-5dbf-a3a1-929f3d16ed6f"
	strings:
		$s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
	condition:
		all of them
}