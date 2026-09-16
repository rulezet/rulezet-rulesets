rule Win_Trojan_Small_139
{
strings:
	$a0 = { 568bfe037401a4a5bf0300b02d8ec060a761b16ff3a4740e8ed9be8400a58944fe8704ab0e1f0e07c3601e3d004b75 }


condition:
	$a0
}