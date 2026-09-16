rule Win_Trojan_Gobleen_2
{
strings:
	$a0 = { e9fb0f00006a00b8ea26400050b815274000506a00e80d0000006affe800000000ff254c304000ff25543040 }


condition:
	$a0
}