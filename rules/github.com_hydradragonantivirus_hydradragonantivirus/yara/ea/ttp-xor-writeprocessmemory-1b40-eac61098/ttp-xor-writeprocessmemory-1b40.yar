rule TTP_XOR_WriteProcessMemory_1b40 {
  strings:
    $key_1b40 = { 4c 32 [2] 7e 10 [2] 78 25 [2] 56 25 [2] 69 39 }

  condition:
    any of them
}