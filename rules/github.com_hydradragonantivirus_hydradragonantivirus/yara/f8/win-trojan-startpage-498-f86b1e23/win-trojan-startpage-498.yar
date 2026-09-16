rule Win_Trojan_Startpage_498
{
strings:
	$a0 = { 22777363222b22726970742e7368656c6c }

	$a1 = { 5c7374222b226172742070616765 }

	$a2 = { 5c73746172222b22742070616765 }


condition:
	$a0 and $a1 and $a2
}