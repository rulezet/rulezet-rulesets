rule Win_Trojan_RNA_2
{
strings:
	$a0 = { 57c43e0c020657b8f01c50bf19021e579ae50bba00e8d3 }


condition:
	$a0
}