rule Win_Trojan_Lineage_100
{
strings:
	$a0 = { 0ab78f03ffb828ea0c6de33815b31dc3fe0e96d6ea1b231aa522ea649b082f6d5998b70e6d5aa41b5752e85ddaaa78001397ac48bfd162515ba84ffe240a500d9807b5a9 }


condition:
	$a0
}