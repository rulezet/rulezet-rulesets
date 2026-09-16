rule TTP_XOR_WriteProcessMemory_ca72 {
  strings:
    $key_ca72 = { 9d 00 [2] af 22 [2] a9 17 [2] 87 17 [2] b8 0b }

  condition:
    any of them
}