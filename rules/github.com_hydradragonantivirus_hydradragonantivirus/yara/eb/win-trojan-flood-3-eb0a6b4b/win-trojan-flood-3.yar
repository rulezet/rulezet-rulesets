rule Win_Trojan_Flood_3
{
strings:
	$a0 = { cd2180fa15740ab409baf801cd21eb1290b409bac101cd21b9e803b8070ecd10e2fce9eb009c }


condition:
	$a0
}