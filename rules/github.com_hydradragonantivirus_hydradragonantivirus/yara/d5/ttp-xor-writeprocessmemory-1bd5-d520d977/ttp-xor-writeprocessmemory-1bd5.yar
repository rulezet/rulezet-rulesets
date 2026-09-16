rule TTP_XOR_WriteProcessMemory_1bd5 {
  strings:
    $key_1bd5 = { 4c a7 [2] 7e 85 [2] 78 b0 [2] 56 b0 [2] 69 ac }

  condition:
    any of them
}