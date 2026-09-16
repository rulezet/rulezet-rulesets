rule Win_Trojan_Small_3994
{
strings:
	$a0 = { 663400e80200000050c35589e583ec70c745f4416c6c6fc745f868612121c645fc21c645 }


condition:
	$a0
}