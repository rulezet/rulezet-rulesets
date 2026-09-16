rule TTP_XOR_WriteProcessMemory_6638 {
  strings:
    $key_6638 = { 31 4a [2] 03 68 [2] 05 5d [2] 2b 5d [2] 14 41 }

  condition:
    any of them
}