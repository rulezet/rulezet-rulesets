rule Win_Trojan_SSR150_1
{
strings:
	$a0 = { e81d00b440595a833cff750acce80b00b440b99600cc071f61ebbdb80242eb03b800422bc999ccc3 }


condition:
	$a0
}