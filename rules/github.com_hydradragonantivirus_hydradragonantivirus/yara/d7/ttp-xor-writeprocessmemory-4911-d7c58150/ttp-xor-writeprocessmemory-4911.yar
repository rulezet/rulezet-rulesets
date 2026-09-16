rule TTP_XOR_WriteProcessMemory_4911 {
  strings:
    $key_4911 = { 1e 63 [2] 2c 41 [2] 2a 74 [2] 04 74 [2] 3b 68 }

  condition:
    any of them
}