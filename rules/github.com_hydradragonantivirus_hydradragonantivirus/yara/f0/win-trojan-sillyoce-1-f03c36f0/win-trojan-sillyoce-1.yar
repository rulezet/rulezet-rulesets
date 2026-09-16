rule Win_Trojan_SillyOCE_1
{
strings:
	$a0 = { 0bc0740ae8520046fe06d60deb08ba710eb43bcd21463b36d30d7ce1803ed6 }


condition:
	$a0
}