rule settings {
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		id = "054b8723-fdfa-51dc-91ae-b915e40b2e54"
	strings:
		$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii 
		$s2 = "<li>Reverse Shell - " fullword ascii 
		$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii 
	condition:
		filesize < 13KB and all of them
}