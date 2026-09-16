rule Win_Trojan_Lamego_1
{
strings:
	$a0 = { b90300ba5b01cd21b8024233d233c9cd21b440b9d202ba0001cd212e8b1e59012e8b1655012e }


condition:
	$a0
}