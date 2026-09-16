rule TTP_XOR_WriteProcessMemory_7911 {
  strings:
    $key_7911 = { 2e 63 [2] 1c 41 [2] 1a 74 [2] 34 74 [2] 0b 68 }

  condition:
    any of them
}