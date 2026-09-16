rule Win_Trojan_Selectron_1
{
strings:
	$a0 = { cd2150b8012ecd21b440b91800baf804cd217225b8024233c933d2cd21c706b4040004b440b9 }


condition:
	$a0
}