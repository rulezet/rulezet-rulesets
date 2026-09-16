rule Trojan_Win32_TrickBotCrypt_EF_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 02 80 f1 80 3b c6 73 21 8d 9b ?? ?? ?? ?? 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7 3b c6 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}