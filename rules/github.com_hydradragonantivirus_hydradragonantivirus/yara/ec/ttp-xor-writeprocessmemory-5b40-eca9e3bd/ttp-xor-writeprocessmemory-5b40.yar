rule TTP_XOR_WriteProcessMemory_5b40 {
  strings:
    $key_5b40 = { 0c 32 [2] 3e 10 [2] 38 25 [2] 16 25 [2] 29 39 }

  condition:
    any of them
}