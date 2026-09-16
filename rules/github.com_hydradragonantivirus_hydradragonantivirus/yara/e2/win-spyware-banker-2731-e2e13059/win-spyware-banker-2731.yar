rule Win_Spyware_Banker_2731
{
strings:
	$a0 = { c97201a37c916c2fb2f7e68693237f9afe29385f0a87b62891304a35f2abba9e7db86b9372bf9ddb2046ee2cfcd009a48cd214c929fc300a0c013fc26631b4ec1422409b7c37190bfab60edf9a0f }


condition:
	$a0
}