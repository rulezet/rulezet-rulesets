rule Win_Trojan_Flavour_3
{
strings:
	$a0 = { ee0300b42acd2181fa0909750bb4098d943b01cd21faebfdb8008fcd213d8f00750f81c62601bf00011657fca5a5 }


condition:
	$a0
}