rule TTP_XOR_WriteProcessMemory_6641 {
  strings:
    $key_6641 = { 31 33 [2] 03 11 [2] 05 24 [2] 2b 24 [2] 14 38 }

  condition:
    any of them
}