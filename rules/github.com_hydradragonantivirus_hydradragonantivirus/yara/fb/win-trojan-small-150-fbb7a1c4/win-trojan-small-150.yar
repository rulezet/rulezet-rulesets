rule Win_Trojan_Small_150
{
strings:
	$a0 = { 8bfee800005e83c62d90a4a5b836008ec033ff2bf060a761b146f3a5740e8ed98d75f8a58944fe8704ab0e1f0e0761 }


condition:
	$a0
}