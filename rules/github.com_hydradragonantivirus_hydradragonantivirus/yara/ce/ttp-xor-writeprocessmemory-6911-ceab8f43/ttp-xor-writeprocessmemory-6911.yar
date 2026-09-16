rule TTP_XOR_WriteProcessMemory_6911 {
  strings:
    $key_6911 = { 3e 63 [2] 0c 41 [2] 0a 74 [2] 24 74 [2] 1b 68 }

  condition:
    any of them
}