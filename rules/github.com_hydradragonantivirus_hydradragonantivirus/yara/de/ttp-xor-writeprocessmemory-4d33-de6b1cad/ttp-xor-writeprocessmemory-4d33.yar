rule TTP_XOR_WriteProcessMemory_4d33 {
  strings:
    $key_4d33 = { 1a 41 [2] 28 63 [2] 2e 56 [2] 00 56 [2] 3f 4a }

  condition:
    any of them
}