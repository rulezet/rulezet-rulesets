rule TTP_XOR_WriteProcessMemory_9cd1 {
  strings:
    $key_9cd1 = { cb a3 [2] f9 81 [2] ff b4 [2] d1 b4 [2] ee a8 }

  condition:
    any of them
}