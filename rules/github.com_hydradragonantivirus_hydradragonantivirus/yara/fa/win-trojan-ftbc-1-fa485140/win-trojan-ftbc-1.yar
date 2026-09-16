rule Win_Trojan_FTBC_1
{
strings:
	$a0 = { 5ec606290100eb29bf00015783c615b91c00f3a4c3b409ba0801cd21c354422d436c65616e }


condition:
	$a0
}