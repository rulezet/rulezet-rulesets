rule Win_Spyware_Banker_3000
{
strings:
	$a0 = { 120e450ba67148dbfbae4b884a1226f88c20ed3a2ad38c4180b9fdd9077ba7e2c0b48788385b196a59d66b9f5ef277823e731ec1fe7c6c774cb8ebcc725135f539e2523f }


condition:
	$a0
}