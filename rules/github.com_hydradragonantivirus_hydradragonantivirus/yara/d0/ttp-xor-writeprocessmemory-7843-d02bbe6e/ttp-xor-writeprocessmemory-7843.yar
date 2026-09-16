rule TTP_XOR_WriteProcessMemory_7843 {
  strings:
    $key_7843 = { 2f 31 [2] 1d 13 [2] 1b 26 [2] 35 26 [2] 0a 3a }

  condition:
    any of them
}