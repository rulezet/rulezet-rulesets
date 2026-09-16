rule TTP_XOR_WriteProcessMemory_6670 {
  strings:
    $key_6670 = { 31 02 [2] 03 20 [2] 05 15 [2] 2b 15 [2] 14 09 }

  condition:
    any of them
}