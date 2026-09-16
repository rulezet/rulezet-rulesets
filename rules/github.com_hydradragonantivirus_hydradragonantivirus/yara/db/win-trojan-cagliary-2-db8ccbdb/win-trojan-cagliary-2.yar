rule Win_Trojan_Cagliary_2
{
strings:
	$a0 = { 4559cd16720c81ff59457506b00233dbcd16fcb8abffcd213d4143752681fb4c47752081f94149751a81fa49 }


condition:
	$a0
}