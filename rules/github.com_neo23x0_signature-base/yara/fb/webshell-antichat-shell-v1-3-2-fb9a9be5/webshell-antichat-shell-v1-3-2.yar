rule webshell_Antichat_Shell_v1_3_2 {
	meta:
		description = "Web Shell - file Antichat Shell v1.3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "40d0abceba125868be7f3f990f031521"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
	condition:
		all of them
}