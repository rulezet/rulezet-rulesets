rule simple_backdoor_php {
	meta:
		description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
		id = "5607f501-a750-59be-9595-5ac71ea6f74b"
	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
	condition:
		2 of them
}