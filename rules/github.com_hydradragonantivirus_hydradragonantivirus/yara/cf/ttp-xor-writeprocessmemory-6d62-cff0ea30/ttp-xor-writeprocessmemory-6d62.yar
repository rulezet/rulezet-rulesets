rule TTP_XOR_WriteProcessMemory_6d62 {
  strings:
    $key_6d62 = { 3a 10 [2] 08 32 [2] 0e 07 [2] 20 07 [2] 1f 1b }

  condition:
    any of them
}