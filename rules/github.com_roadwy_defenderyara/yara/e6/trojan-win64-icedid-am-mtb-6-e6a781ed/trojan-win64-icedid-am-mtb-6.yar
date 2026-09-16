rule Trojan_Win64_IcedID_AM_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0a 48 ff c2 41 88 08 4d 8d 40 01 48 83 e8 01 75 ed 45 0f b7 4d 14 45 0f b7 55 06 49 83 c1 2c 4d 85 d2 74 45 4d 03 cd 0f 1f 80 00 00 00 00 41 8b 49 f8 49 ff ca 41 8b 11 49 03 ce 45 8b 41 fc 48 03 d5 4d 85 c0 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}