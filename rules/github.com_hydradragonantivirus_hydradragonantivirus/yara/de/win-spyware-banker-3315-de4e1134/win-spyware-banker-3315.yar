rule Win_Spyware_Banker_3315
{
strings:
	$a0 = { 63f09e382d4dc6d85fb41af0d8e66f826d969cae37bf29f1ea9011b1fc16e2a0e0c15aa634bbe84d85cd647741901a9187c36b0ea0c50e81d9c02b405e0965e0c5fe3e47f433 }


condition:
	$a0
}