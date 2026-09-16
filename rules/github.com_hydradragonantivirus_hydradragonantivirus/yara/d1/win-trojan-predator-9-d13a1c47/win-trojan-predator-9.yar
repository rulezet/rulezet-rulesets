rule Win_Trojan_Predator_9
{
strings:
	$a0 = { 07b888ffcd213db8227503eb2090071f5d5f5e5a59 }


condition:
	$a0
}