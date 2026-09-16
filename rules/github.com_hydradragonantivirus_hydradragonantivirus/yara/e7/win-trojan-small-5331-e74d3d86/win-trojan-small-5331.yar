rule Win_Trojan_Small_5331
{
strings:
	$a0 = { 60349ca6ac1479f75dbf91d320cc141771aa57841caba3db21ebd574740fe638d1bf9150b518fb51b41eefadb782e6db4811e2a3b2161cce6442f6585c4ad88c5f86a007a5c5161ae60c8dcf9b4c }


condition:
	$a0
}