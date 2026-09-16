rule Win_Trojan_Goma_17
{
strings:
	$a0 = { 81fabbfc777383fa0e726e81ea44023e3b964803746381c244023e899645038d964703cd21 }


condition:
	$a0
}