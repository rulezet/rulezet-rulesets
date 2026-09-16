rule Win_Trojan_Vac_1
{
strings:
	$a0 = { 0688000700cdec2204cdb2be7401cd96cdb8cdb2cdec4c70010000cdec9abe2001cd9abe2001cd }


condition:
	$a0
}