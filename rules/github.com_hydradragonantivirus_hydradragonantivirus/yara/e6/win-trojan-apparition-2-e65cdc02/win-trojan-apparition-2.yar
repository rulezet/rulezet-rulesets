rule Win_Trojan_Apparition_2
{
strings:
	$a0 = { 03d6b90e11b4408b9c7412cd21b800428b9c7412b90000ba0000cd21b4408b9c7412b92000 }


condition:
	$a0
}