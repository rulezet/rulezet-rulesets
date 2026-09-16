rule Win_Trojan_Arusiek_1
{
strings:
	$a0 = { 1635cd21891e35038c063703b021cd21891e31038c063303ba2801b425cd21b42acd2181f9ca07 }


condition:
	$a0
}