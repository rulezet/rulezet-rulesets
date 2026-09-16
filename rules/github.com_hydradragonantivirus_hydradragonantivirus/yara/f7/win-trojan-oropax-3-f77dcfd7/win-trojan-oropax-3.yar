rule Win_Trojan_Oropax_3
{
strings:
	$a0 = { 069c007d098c0e9e00c7068400ee088c0e8600fb2e803e070100 }


condition:
	$a0
}