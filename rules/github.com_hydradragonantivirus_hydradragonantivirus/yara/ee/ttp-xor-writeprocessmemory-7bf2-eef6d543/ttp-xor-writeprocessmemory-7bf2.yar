rule TTP_XOR_WriteProcessMemory_7bf2 {
  strings:
    $key_7bf2 = { 2c 80 [2] 1e a2 [2] 18 97 [2] 36 97 [2] 09 8b }

  condition:
    any of them
}