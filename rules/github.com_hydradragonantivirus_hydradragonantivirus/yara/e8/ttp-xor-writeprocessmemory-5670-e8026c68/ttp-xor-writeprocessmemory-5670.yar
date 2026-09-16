rule TTP_XOR_WriteProcessMemory_5670 {
  strings:
    $key_5670 = { 01 02 [2] 33 20 [2] 35 15 [2] 1b 15 [2] 24 09 }

  condition:
    any of them
}