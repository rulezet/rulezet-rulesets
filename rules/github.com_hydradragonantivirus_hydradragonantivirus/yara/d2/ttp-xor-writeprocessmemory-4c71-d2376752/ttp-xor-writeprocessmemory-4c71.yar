rule TTP_XOR_WriteProcessMemory_4c71 {
  strings:
    $key_4c71 = { 1b 03 [2] 29 21 [2] 2f 14 [2] 01 14 [2] 3e 08 }

  condition:
    any of them
}