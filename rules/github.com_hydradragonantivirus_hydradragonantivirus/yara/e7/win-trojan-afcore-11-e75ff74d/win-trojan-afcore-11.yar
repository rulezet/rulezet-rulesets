rule Win_Trojan_Afcore_11
{
strings:
	$a0 = { 4146434f52450056657273696f6e20322e }

	$a1 = { 64733d2568004f63746f707573205049443a2025 }


condition:
	$a0 and $a1
}