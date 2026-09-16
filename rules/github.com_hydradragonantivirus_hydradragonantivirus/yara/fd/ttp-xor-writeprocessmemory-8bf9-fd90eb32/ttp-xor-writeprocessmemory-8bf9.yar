rule TTP_XOR_WriteProcessMemory_8bf9 {
  strings:
    $key_8bf9 = { dc 8b [2] ee a9 [2] e8 9c [2] c6 9c [2] f9 80 }

  condition:
    any of them
}