rule Win_Trojan_MyChild_1
{
strings:
	$a0 = { ee0350b47acd213ca77515e9e2004d79204368696c642e2e2e024b2d6f6e2d415351520e8d84f10050560633ffb4 }


condition:
	$a0
}