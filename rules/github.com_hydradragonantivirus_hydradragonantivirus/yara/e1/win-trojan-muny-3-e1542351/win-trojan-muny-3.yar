rule Win_Trojan_Muny_3
{
strings:
	$a0 = { 0cf873342d030050b440b96c018d960001cd21b800429933c9cd21582ec6866802e92e89866902 }


condition:
	$a0
}