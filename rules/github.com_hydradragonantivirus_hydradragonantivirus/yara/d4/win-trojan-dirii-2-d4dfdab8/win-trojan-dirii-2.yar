rule Win_Trojan_DirII_2
{
strings:
	$a0 = { ff06eb0431c98ed9c506c1000521001e50b430e824013c0419f6c6066504ffbb6000b44ae81301b452e80e01 }


condition:
	$a0
}