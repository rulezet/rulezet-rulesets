rule TTP_XOR_WriteProcessMemory_4c32 {
  strings:
    $key_4c32 = { 1b 40 [2] 29 62 [2] 2f 57 [2] 01 57 [2] 3e 4b }

  condition:
    any of them
}