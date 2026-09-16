rule TTP_XOR_WriteProcessMemory_0bd5 {
  strings:
    $key_0bd5 = { 5c a7 [2] 6e 85 [2] 68 b0 [2] 46 b0 [2] 79 ac }

  condition:
    any of them
}