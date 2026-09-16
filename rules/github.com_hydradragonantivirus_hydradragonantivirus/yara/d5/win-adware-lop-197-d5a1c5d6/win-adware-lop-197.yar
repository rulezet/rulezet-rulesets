rule Win_Adware_Lop_197
{
strings:
	$a0 = { 7e9122c37ac6920a9c1b1f479ffd43740359d53c38ebad2dc156d6465607eed405242c5be3a39ecff2c55b099830bcf64809c23ccea2863b19981b1b }


condition:
	$a0
}