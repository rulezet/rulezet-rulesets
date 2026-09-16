rule Win_Trojan_Mini_13
{
strings:
	$a0 = { cd21bafaffb44ecd217234b891d9bae2fbf7eacd2193b43f8bd6b5fccd213bc17429803c4d74 }


condition:
	$a0
}