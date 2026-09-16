rule Win_Trojan_Marian_1
{
strings:
	$a0 = { 8bd7b0e8aa582d0300abb84f4dabb440b90500e835ffe99100a1c5033b06cd037503e98500 }


condition:
	$a0
}