rule Trojan_Win32_Neoreblamy_GMH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 8a 1c 01 8d 50 56 8a cb e8 ?? ?? ?? ?? 0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}