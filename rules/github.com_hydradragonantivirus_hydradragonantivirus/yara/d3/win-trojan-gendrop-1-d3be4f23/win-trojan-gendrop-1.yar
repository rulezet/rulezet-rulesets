rule Win_Trojan_GenDrop_1
{
strings:
	$a0 = { 0133c9cd2150b80009cd21585a1f598bd8b80040cd21b43ecd210e1fbf8701bb0700fe018039 }


condition:
	$a0
}