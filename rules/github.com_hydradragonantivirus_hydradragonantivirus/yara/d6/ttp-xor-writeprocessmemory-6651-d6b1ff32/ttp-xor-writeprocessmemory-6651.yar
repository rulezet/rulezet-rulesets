rule TTP_XOR_WriteProcessMemory_6651 {
  strings:
    $key_6651 = { 31 23 [2] 03 01 [2] 05 34 [2] 2b 34 [2] 14 28 }

  condition:
    any of them
}