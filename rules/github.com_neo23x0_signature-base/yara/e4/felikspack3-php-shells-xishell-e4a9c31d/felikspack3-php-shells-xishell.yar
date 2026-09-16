rule FeliksPack3___PHP_Shells_xIShell {
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "997c8437c0621b4b753a546a53a88674"
		id = "32a32a9a-8d5f-5b3f-8ff4-560555f0ae1e"
	strings:
		$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
	condition:
		all of them
}