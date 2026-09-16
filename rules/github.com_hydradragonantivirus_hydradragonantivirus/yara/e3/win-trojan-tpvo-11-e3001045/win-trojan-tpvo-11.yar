rule Win_Trojan_TPVO_11
{
strings:
	$a0 = { 3003e828027236e81b022d0300a32e03b440b9330333d2e813027221e8fc01b440b90300ba2d03 }


condition:
	$a0
}