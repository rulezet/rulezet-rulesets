rule TTP_XOR_WriteProcessMemory_5c31 {
  strings:
    $key_5c31 = { 0b 43 [2] 39 61 [2] 3f 54 [2] 11 54 [2] 2e 48 }

  condition:
    any of them
}