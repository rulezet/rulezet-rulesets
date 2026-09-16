rule TTP_XOR_WriteProcessMemory_9cdd {
  strings:
    $key_9cdd = { cb af [2] f9 8d [2] ff b8 [2] d1 b8 [2] ee a4 }

  condition:
    any of them
}