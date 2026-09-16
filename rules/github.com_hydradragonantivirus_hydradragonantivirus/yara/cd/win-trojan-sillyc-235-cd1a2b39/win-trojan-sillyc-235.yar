rule Win_Trojan_SillyC_235
{
strings:
	$a0 = { cd2180bc0001e9751a80bc02013f741333c933d2b80242cd213d00027205b43ecd21c3e8f8ff }


condition:
	$a0
}