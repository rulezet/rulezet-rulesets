rule TTP_XOR_WriteProcessMemory_0b13 {
  strings:
    $key_0b13 = { 5c 61 [2] 6e 43 [2] 68 76 [2] 46 76 [2] 79 6a }

  condition:
    any of them
}