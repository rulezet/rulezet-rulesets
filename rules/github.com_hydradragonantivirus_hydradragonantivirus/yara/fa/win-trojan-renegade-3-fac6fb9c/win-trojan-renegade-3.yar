rule Win_Trojan_Renegade_3
{
strings:
	$a0 = { 2e8b16130483ea072e89161304b106d3e28ec233dbb80902b90900ba8000cd130668c202cb06 }


condition:
	$a0
}