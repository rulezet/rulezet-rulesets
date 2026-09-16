rule TTP_XOR_WriteProcessMemory_32e2 {
  strings:
    $key_32e2 = { 65 90 [2] 57 b2 [2] 51 87 [2] 7f 87 [2] 40 9b }

  condition:
    any of them
}