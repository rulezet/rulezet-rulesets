rule TTP_XOR_WriteProcessMemory_7e96 {
  strings:
    $key_7e96 = { 29 e4 [2] 1b c6 [2] 1d f3 [2] 33 f3 [2] 0c ef }

  condition:
    any of them
}