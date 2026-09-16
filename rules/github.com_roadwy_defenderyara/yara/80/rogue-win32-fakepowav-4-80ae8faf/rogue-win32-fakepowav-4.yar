rule Rogue_Win32_FakePowav_4{
	meta:
		description = "Rogue:Win32/FakePowav,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb eb 5f 5e 5b e8 ?? ?? ?? ?? 00 ff ff ff ff 20 00 00 00 38 33 32 31 37 32 41 30 41 43 39 45 46 32 37 35 35 44 41 46 44 30 35 45 37 37 45 33 35 41 32 34 00 00 00 00 ff ff ff ff 0a 00 00 00 2d 75 6e 69 6e 73 74 61 6c 6c 00 00 ff ff ff ff 0a 00 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}