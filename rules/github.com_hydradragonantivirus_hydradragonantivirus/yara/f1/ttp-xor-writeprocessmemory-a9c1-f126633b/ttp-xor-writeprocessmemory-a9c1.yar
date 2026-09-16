rule TTP_XOR_WriteProcessMemory_a9c1 {
  strings:
    $key_a9c1 = { fe b3 [2] cc 91 [2] ca a4 [2] e4 a4 [2] db b8 }

  condition:
    any of them
}