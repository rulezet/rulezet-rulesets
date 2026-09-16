rule TTP_XOR_WriteProcessMemory_ca02 {
  strings:
    $key_ca02 = { 9d 70 [2] af 52 [2] a9 67 [2] 87 67 [2] b8 7b }

  condition:
    any of them
}