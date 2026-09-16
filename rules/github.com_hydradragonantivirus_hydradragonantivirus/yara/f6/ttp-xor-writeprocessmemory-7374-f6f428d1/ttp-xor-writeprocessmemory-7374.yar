rule TTP_XOR_WriteProcessMemory_7374 {
  strings:
    $key_7374 = { 24 06 [2] 16 24 [2] 10 11 [2] 3e 11 [2] 01 0d }

  condition:
    any of them
}