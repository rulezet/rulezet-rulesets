rule Win_Trojan_Australian_16
{
strings:
	$a0 = { bd0a008db6f101bf000157a5a4b8a054cd213d0112743f1e58488ec08b1e020081eb1400891e020026812e0300140083 }


condition:
	$a0
}