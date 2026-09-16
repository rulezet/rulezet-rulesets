rule Trojan_Win32_NSISInject_RB_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 6a 0c 59 f7 f9 8b 45 bc 0f b6 04 10 8b 4d ec 03 4d f4 0f b6 09 33 c8 8b 45 ec 03 45 f4 88 08 eb cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}