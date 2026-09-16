rule TTP_XOR_WriteProcessMemory_a041 {
  strings:
    $key_a041 = { f7 33 [2] c5 11 [2] c3 24 [2] ed 24 [2] d2 38 }

  condition:
    any of them
}