rule TTP_XOR_WriteProcessMemory_4162 {
  strings:
    $key_4162 = { 16 10 [2] 24 32 [2] 22 07 [2] 0c 07 [2] 33 1b }

  condition:
    any of them
}