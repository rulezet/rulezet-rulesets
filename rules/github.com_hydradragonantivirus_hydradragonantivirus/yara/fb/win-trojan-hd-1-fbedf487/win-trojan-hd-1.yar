rule Win_Trojan_Hd_1
{
strings:
	$a0 = { 68b2dbaecc }

	$a1 = { c704240f09e40e }

	$a2 = { 31d0f6da31c8 }

	$a3 = { 68ec8f289289042468f3352b37 }


condition:
	$a0 and $a1 and $a2 and $a3
}