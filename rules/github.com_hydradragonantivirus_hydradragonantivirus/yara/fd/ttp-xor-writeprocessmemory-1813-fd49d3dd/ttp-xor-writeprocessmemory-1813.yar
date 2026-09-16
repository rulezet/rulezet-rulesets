rule TTP_XOR_WriteProcessMemory_1813 {
  strings:
    $key_1813 = { 4f 61 [2] 7d 43 [2] 7b 76 [2] 55 76 [2] 6a 6a }

  condition:
    any of them
}