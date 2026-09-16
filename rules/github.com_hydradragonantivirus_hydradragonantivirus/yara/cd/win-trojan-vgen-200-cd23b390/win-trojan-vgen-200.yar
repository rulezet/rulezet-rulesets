rule Win_Trojan_VGEN_200
{
strings:
	$a0 = { bd0400cd038d8e8703ffd192a31f4a0b0bac3e290f9430290fb43f297ddd5bdd5bd137df33dfaafb57a711dc85e7a634 }


condition:
	$a0
}