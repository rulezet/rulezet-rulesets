rule TTP_XOR_WriteProcessMemory_8bf0 {
  strings:
    $key_8bf0 = { dc 82 [2] ee a0 [2] e8 95 [2] c6 95 [2] f9 89 }

  condition:
    any of them
}