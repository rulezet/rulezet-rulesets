rule WebShell_php_webshells_myshell_2 {
	meta:
		description = "PHP Webshells Github Archive - file myshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_php_webshells_myshell"
		hash = "5bd52749872d1083e7be076a5e65ffcde210e524"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
		$s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
		$s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
		$s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
	condition:
		1 of them
}