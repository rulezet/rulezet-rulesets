rule TTP_XOR_WriteProcessMemory_8dcc {
  strings:
    $key_8dcc = { da be [2] e8 9c [2] ee a9 [2] c0 a9 [2] ff b5 }

  condition:
    any of them
}