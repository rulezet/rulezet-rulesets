rule Win_Trojan_Ply_5
{
strings:
	$a0 = { e85e08908ed8e9ae0fb800012be890fb9090fc9090be0301e96c0cb9b601e92a0c2407905190905690903c0090 }


condition:
	$a0
}