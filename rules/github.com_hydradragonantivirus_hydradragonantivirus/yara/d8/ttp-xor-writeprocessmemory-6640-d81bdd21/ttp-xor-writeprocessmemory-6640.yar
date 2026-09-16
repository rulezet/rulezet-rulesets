rule TTP_XOR_WriteProcessMemory_6640 {
  strings:
    $key_6640 = { 31 32 [2] 03 10 [2] 05 25 [2] 2b 25 [2] 14 39 }

  condition:
    any of them
}