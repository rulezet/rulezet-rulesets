rule TTP_XOR_WriteProcessMemory_1936 {
  strings:
    $key_1936 = { 4e 44 [2] 7c 66 [2] 7a 53 [2] 54 53 [2] 6b 4f }

  condition:
    any of them
}