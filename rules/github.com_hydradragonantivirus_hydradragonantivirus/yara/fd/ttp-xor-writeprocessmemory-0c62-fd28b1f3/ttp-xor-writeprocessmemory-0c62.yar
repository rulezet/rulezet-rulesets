rule TTP_XOR_WriteProcessMemory_0c62 {
  strings:
    $key_0c62 = { 5b 10 [2] 69 32 [2] 6f 07 [2] 41 07 [2] 7e 1b }

  condition:
    any of them
}