rule TTP_XOR_WriteProcessMemory_6b62 {
  strings:
    $key_6b62 = { 3c 10 [2] 0e 32 [2] 08 07 [2] 26 07 [2] 19 1b }

  condition:
    any of them
}