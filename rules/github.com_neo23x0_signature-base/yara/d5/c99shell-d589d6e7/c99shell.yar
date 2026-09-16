rule c99shell {
	meta:
		description = "Webshells Auto-generated - file c99shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "90b86a9c63e2cd346fe07cea23fbfc56"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
	condition:
		all of them
}