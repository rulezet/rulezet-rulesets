rule Win_Trojan_Kunsr_1
{
strings:
	$a0 = { 803c4d74c1803ce97529484848874401050301394401721b89445c89545eba2e00b440cd21b8 }


condition:
	$a0
}