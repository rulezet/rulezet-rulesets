rule Win_Trojan_Trash_3
{
strings:
	$a0 = { b80006b707ba501933c9cd10b40fcd10b40233d2cd10b409ba1103cd21b8080ccd213c007510b408cd213c6c7508b402 }


condition:
	$a0
}