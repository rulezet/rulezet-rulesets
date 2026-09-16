rule Win_Trojan_Mini_84
{
strings:
	$a0 = { b44e8bd6cd217301c3b8023d99b29ecd2193b43f5459ba3e0190cd21807c3e2a907412fec45033c9f7e1b442cd218bd659b440cd21b44febcb }


condition:
	$a0
}