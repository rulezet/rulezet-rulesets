rule TTP_XOR_WriteProcessMemory_4b22 {
  strings:
    $key_4b22 = { 1c 50 [2] 2e 72 [2] 28 47 [2] 06 47 [2] 39 5b }

  condition:
    any of them
}