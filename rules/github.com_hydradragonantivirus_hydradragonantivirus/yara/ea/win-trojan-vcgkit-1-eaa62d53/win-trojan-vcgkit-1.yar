rule Win_Trojan_VcgKit_1
{
strings:
	$a0 = { 341281eeffd181c633e781eeffd481ea05d281c200fd81c2ffd4525d87d187d1cd2156552bed }


condition:
	$a0
}