rule TTP_XOR_WriteProcessMemory_3b60 {
  strings:
    $key_3b60 = { 6c 12 [2] 5e 30 [2] 58 05 [2] 76 05 [2] 49 19 }

  condition:
    any of them
}