rule webshell_PHP_a : webshell {
	meta:
		description = "Web Shell - file a.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e3b461f7464d81f5022419d87315a90d"
	strings:
		$s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
		$s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
		$s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
	condition:
		2 of them
}