rule Win_Trojan_Small_194
{
strings:
	$a0 = { cd21b82135cd21895c578c4459b425ba1901cd2192cd270040750c58568bfebe5701b5fcf3a4cf48601e80fc407524 }


condition:
	$a0
}