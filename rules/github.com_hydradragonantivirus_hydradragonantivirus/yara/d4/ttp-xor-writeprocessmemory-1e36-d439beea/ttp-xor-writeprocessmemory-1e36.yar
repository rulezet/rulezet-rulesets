rule TTP_XOR_WriteProcessMemory_1e36 {
  strings:
    $key_1e36 = { 49 44 [2] 7b 66 [2] 7d 53 [2] 53 53 [2] 6c 4f }

  condition:
    any of them
}