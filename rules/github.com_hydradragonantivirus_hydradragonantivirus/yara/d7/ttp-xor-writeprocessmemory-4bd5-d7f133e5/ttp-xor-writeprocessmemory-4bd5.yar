rule TTP_XOR_WriteProcessMemory_4bd5 {
  strings:
    $key_4bd5 = { 1c a7 [2] 2e 85 [2] 28 b0 [2] 06 b0 [2] 39 ac }

  condition:
    any of them
}