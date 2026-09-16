rule TTP_XOR_WriteProcessMemory_6b40 {
  strings:
    $key_6b40 = { 3c 32 [2] 0e 10 [2] 08 25 [2] 26 25 [2] 19 39 }

  condition:
    any of them
}