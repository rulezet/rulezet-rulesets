rule Win_Trojan_Silly_42
{
strings:
	$a0 = { b8024233c999cd2183e80383c7088905b440b16a8bd781ea6a00e80a004fb440b1038bd7cd21 }


condition:
	$a0
}