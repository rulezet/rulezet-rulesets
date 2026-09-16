rule Win_Trojan_Tanpro_1
{
strings:
	$a0 = { 350b1101e610050005001811601e063d004b7403e91a01fc8cd88ec08bfab000b9fffff2 }


condition:
	$a0
}