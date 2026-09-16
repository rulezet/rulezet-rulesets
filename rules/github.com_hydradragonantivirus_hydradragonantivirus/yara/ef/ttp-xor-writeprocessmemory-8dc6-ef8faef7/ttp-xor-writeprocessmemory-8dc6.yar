rule TTP_XOR_WriteProcessMemory_8dc6 {
  strings:
    $key_8dc6 = { da b4 [2] e8 96 [2] ee a3 [2] c0 a3 [2] ff bf }

  condition:
    any of them
}