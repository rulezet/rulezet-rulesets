rule TTP_XOR_WriteProcessMemory_2cf0 {
  strings:
    $key_2cf0 = { 7b 82 [2] 49 a0 [2] 4f 95 [2] 61 95 [2] 5e 89 }

  condition:
    any of them
}