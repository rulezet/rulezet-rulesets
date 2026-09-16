rule Win_Trojan_Eleet_1
{
strings:
	$a0 = { 02050004a3ed02b9d60233d2b440e85300e84900b90002f7f183fa00740140a3e5028916e302 }


condition:
	$a0
}