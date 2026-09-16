rule Win_Trojan_Vienna_2
{
strings:
	$a0 = { be000356c3 }

	$a1 = { 50be????8bd6fcb90500bf0001f3a48bfab430cd21 }


condition:
	$a0 and $a1
}