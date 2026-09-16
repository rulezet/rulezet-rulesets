rule Win_Trojan_EraseHDD_1
{
strings:
	$a0 = { c98bd1fec180d6000ac97502fec1b280b801039aee037000ebe9 }


condition:
	$a0
}