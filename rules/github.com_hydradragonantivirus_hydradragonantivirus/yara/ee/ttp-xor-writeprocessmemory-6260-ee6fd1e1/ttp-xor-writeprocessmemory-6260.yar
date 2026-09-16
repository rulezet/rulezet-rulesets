rule TTP_XOR_WriteProcessMemory_6260 {
  strings:
    $key_6260 = { 35 12 [2] 07 30 [2] 01 05 [2] 2f 05 [2] 10 19 }

  condition:
    any of them
}