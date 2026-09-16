rule Win_Trojan_Myon_1
{
strings:
	$a0 = { 5e009a46025e00e9e400bfe6011e57bf66021e57b8dd0d50bf44101e579aa309 }


condition:
	$a0
}