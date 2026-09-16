rule TTP_XOR_WriteProcessMemory_6977 {
  strings:
    $key_6977 = { 3e 05 [2] 0c 27 [2] 0a 12 [2] 24 12 [2] 1b 0e }

  condition:
    any of them
}