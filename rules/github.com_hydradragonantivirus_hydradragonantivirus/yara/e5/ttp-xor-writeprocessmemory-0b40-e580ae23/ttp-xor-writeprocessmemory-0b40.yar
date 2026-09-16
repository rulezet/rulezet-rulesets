rule TTP_XOR_WriteProcessMemory_0b40 {
  strings:
    $key_0b40 = { 5c 32 [2] 6e 10 [2] 68 25 [2] 46 25 [2] 79 39 }

  condition:
    any of them
}