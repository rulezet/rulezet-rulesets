rule TTP_XOR_WriteProcessMemory_4560 {
  strings:
    $key_4560 = { 12 12 [2] 20 30 [2] 26 05 [2] 08 05 [2] 37 19 }

  condition:
    any of them
}