rule Win_Trojan_Ieronim_7
{
strings:
	$a0 = { 02f7d88bc8b440cd21803eee010175338b163214a134142e8b363614803ef1014b75161e8e }


condition:
	$a0
}