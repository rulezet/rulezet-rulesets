rule Win_Trojan_Trojan_306
{
strings:
	$a0 = { 5bcd217305ba8c02ebe18bd8b90002ba6c06b440cd217305bae002ebceb43ecd21b9ac00bb1405 }


condition:
	$a0
}