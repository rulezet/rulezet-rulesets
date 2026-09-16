rule Win_Trojan_unk_1
{
strings:
	$a0 = { a20e008ed9be4c0056bf6900a5a51e075fb86300abb82000ab0e1f33f6bf0002b90001f3a40e5801 }


condition:
	$a0
}