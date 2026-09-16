rule Win_Trojan_Dumador_57
{
strings:
	$a0 = { 0fbaf8570fbcc00fbdff0fc1da4f0fbbc28d055c83cb16f6c4930facdbf4428d1500f767a388c6c1cfb9 }


condition:
	$a0
}