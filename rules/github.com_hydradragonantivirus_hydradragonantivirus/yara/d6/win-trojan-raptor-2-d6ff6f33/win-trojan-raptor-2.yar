rule Win_Trojan_Raptor_2
{
strings:
	$a0 = { 50b06ea28306b04ea23c06b4408b1e5b06b90807ba0001cd21583c597515 }


condition:
	$a0
}