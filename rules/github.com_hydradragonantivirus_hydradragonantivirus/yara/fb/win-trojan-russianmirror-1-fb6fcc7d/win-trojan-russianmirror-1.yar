rule Win_Trojan_RussianMirror_1
{
strings:
	$a0 = { a3be015b53b9e201ba0000b440cd21b800425b53b90000ba0000cd21 }


condition:
	$a0
}