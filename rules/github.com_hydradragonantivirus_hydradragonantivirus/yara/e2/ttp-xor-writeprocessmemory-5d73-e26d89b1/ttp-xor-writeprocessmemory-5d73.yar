rule TTP_XOR_WriteProcessMemory_5d73 {
  strings:
    $key_5d73 = { 0a 01 [2] 38 23 [2] 3e 16 [2] 10 16 [2] 2f 0a }

  condition:
    any of them
}