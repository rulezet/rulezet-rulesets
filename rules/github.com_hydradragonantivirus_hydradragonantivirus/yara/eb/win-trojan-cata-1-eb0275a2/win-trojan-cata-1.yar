rule Win_Trojan_Cata_1
{
strings:
	$a0 = { 1e062bc08ed8bf4002bea2003975017505ea40020000c605ea897501571e060e1f1e07b93c028db655008b54c3908b }


condition:
	$a0
}