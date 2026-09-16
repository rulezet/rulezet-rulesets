rule Win_Trojan_SillyC_160
{
strings:
	$a0 = { cd2180fe037513b403ba8000b90100b0010e07bb1b01cd13cd18b44a2e8b1e000281c30e0251b104d3eb4359cd }


condition:
	$a0
}