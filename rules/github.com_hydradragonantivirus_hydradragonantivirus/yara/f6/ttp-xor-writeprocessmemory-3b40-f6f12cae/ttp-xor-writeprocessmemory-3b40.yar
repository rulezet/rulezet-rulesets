rule TTP_XOR_WriteProcessMemory_3b40 {
  strings:
    $key_3b40 = { 6c 32 [2] 5e 10 [2] 58 25 [2] 76 25 [2] 49 39 }

  condition:
    any of them
}