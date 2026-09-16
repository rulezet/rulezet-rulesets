rule ImportTableIsBad : PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ImportTable Check"
	condition:
				uint16(0) == 0x5A4D and
				uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 				((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))     > (uint32(uint32(0x3C)+0x50)) 
		or
		(((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))  == 0x0)
		
				
										
						
		
								
		
		or
				(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) > filesize)

				   						)				
}