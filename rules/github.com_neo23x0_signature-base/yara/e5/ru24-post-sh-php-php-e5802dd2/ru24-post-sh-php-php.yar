rule ru24_post_sh_php_php {
	meta:
		description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5b334d494564393f419af745dc1eeec7"
		id = "78669d3e-629b-591a-a766-923e37d1fdba"
	strings:
		$s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
		$s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s4 = "Writed by DreAmeRz" fullword
	condition:
		1 of them
}