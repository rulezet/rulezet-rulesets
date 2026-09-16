rule Win_Trojan_XRes_7
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd218b1e4e03b8feffba5d03cd219089 }


condition:
	$a0
}