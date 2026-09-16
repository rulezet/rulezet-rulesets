rule Win_Trojan_X_5
{
strings:
	$a0 = { 012e8c9c0e01b83254cd213d041075152e80bc2e01 }


condition:
	$a0
}