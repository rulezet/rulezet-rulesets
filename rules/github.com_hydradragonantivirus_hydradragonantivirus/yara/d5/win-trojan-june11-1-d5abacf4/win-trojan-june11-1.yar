rule Win_Trojan_June11_1
{
strings:
	$a0 = { 0e1f07be7c018b3e560181c7007cb92400fcf3a4e8270080fa807403e8e100c70654010000b404cd1a80fe06750b80 }


condition:
	$a0
}