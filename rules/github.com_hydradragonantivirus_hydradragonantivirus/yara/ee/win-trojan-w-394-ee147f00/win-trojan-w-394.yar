rule Win_Trojan_W_394
{
strings:
	$a0 = { 8b05a3104000bd68b480c43102b7bdb7fa83c204bfffded2414503052a1040004bc1c8064b4d490f84a2e9ffff4debd6 }


condition:
	$a0
}