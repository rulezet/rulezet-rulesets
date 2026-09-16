rule Win_Trojan_FITW_1
{
strings:
	$a0 = { cd133d544574240e0733c08ed8be4c00bf3301fca5a58cc88ed8ba8000b90100b80102bb0010e8c60f7303e9bf }


condition:
	$a0
}