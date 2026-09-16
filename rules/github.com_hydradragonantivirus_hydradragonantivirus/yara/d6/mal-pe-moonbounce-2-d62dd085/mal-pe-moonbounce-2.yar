rule MAL_PE_MOONBOUNCE_2 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule generated using MCRIT for code family MOONBOUNCE."
    reference   = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/01/19115831/MoonBounce_technical-details_eng.pdf"
    DaysofYARA  = "11/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-27"
    version     = "1.0"

  strings:
        
    $blockhash_0x48ea83dce36c4626 = {
      55 8b ec 83 ec 10 53 56 57 8b 7d 08 8b 07 8b 70 3c 6a 04 03 f0 68 00 20 00 00 ff 76 50 ff 76 34
      ff 57 08 8b d8 85 db 75 ??
    }
    
    $blockhash_0x764296061a725128 = {
      55 8b ec 68 2e 09 01 00 ff 15 ?? ?? ?? ?? 6a 00 ff 75 08 ff 15 ?? ?? ?? ?? 5d c2 14 00
    }
    
    $blockhash_0x49a88ff260995656 = {
      55 8b ec 53 56 57 6a 30 33 ff 57 ff 15 ?? ?? ?? ?? 8b 75 08 8b d8 3b df 74 ??
    }
    
    $blockhash_0xde8b1927abca2188 = {
      8b ff 55 8b ec 83 ec 30 53 33 db 53 ff 75 08 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 8d 45 fc 50 53
      8d 45 08 50 6a ff 89 5d 08 c7 45 fc 00 10 04 00 ff 15 ?? ?? ?? ?? 85 c0 0f 8c ?? ?? ?? ??
    }
    
    $blockhash_0x5d9f8f062412cf05 = {
      55 8b ec 83 ec 18 83 7d 08 00 0f 84 ?? ?? ?? ??
    }

  condition:
    uint16(0) == 0x5A4D
    and (uint32(uint32(0x3C)) == 0x00004550)
    and uint16(uint32(0x3C) + 0x18) == 0x20b
    and any of them
}