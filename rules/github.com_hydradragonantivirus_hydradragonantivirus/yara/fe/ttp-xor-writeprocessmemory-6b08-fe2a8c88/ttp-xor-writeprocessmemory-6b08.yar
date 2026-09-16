rule TTP_XOR_WriteProcessMemory_6b08 {
  strings:
    $key_6b08 = { 3c 7a [2] 0e 58 [2] 08 6d [2] 26 6d [2] 19 71 }

  condition:
    any of them
}