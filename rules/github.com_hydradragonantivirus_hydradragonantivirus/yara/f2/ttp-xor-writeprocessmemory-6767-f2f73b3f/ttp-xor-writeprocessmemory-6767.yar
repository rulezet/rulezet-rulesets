rule TTP_XOR_WriteProcessMemory_6767 {
  strings:
    $key_6767 = { 30 15 [2] 02 37 [2] 04 02 [2] 2a 02 [2] 15 1e }

  condition:
    any of them
}