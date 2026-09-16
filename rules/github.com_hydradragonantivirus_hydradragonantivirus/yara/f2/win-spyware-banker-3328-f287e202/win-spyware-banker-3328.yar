rule Win_Spyware_Banker_3328
{
strings:
	$a0 = { 16e258e98422c4c3c1cf3ca2fd23b02b00441b0f608dafb240c297e8fe127bfc777fa322f5034e04cce36bbd1b23dbf6e35783c2d4d797f75d1d98fb759cf520c1237220129f }


condition:
	$a0
}