rule TTP_XOR_WriteProcessMemory_7d43 {
  strings:
    $key_7d43 = { 2a 31 [2] 18 13 [2] 1e 26 [2] 30 26 [2] 0f 3a }

  condition:
    any of them
}