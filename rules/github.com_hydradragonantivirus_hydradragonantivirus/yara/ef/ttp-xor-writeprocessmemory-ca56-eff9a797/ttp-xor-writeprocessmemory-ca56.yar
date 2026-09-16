rule TTP_XOR_WriteProcessMemory_ca56 {
  strings:
    $key_ca56 = { 9d 24 [2] af 06 [2] a9 33 [2] 87 33 [2] b8 2f }

  condition:
    any of them
}