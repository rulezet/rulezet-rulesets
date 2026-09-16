rule Win_Trojan_Vgen_152
{
strings:
	$a0 = { 02b90100ba0000b0010e07bb0008cd137303e9ea0831c0a3f909a3fb09b403b90100ba0000b0010e07bb0008cd1373 }


condition:
	$a0
}