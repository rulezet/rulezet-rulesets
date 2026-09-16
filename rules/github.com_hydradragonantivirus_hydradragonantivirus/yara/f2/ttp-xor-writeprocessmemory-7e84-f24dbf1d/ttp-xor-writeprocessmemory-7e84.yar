rule TTP_XOR_WriteProcessMemory_7e84 {
  strings:
    $key_7e84 = { 29 f6 [2] 1b d4 [2] 1d e1 [2] 33 e1 [2] 0c fd }

  condition:
    any of them
}