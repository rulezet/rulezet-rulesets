rule TTP_XOR_WriteProcessMemory_7367 {
  strings:
    $key_7367 = { 24 15 [2] 16 37 [2] 10 02 [2] 3e 02 [2] 01 1e }

  condition:
    any of them
}