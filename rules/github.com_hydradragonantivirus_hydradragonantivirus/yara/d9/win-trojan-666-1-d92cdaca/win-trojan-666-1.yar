rule Win_Trojan_666_1
{
strings:
	$a0 = { 8ed9bff800a5a5be8400a5a5c544fc0657be0800b5 }


condition:
	$a0
}