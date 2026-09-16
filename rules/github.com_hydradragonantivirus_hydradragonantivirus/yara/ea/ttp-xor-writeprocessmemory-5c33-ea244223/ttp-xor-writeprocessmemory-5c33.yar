rule TTP_XOR_WriteProcessMemory_5c33 {
  strings:
    $key_5c33 = { 0b 41 [2] 39 63 [2] 3f 56 [2] 11 56 [2] 2e 4a }

  condition:
    any of them
}