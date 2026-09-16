rule Win_Spyware_Banker_6189
{
strings:
	$a0 = { 31752a004218833e2126d7c80bb565a4c380e8b32549620af7448408ed031871e387988f9a7500631efecc5bd2aa9d00 }


condition:
	$a0
}