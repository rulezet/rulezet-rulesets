rule Win_Trojan_Small_1101
{
strings:
	$a0 = { 676a326c632a28217c[0-5]496e7374616c6c486f6f6b0063686172[0-2]6f7265 }


condition:
	$a0
}