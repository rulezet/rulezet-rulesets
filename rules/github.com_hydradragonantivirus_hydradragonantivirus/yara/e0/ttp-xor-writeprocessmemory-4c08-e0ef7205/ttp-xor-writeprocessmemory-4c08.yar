rule TTP_XOR_WriteProcessMemory_4c08 {
  strings:
    $key_4c08 = { 1b 7a [2] 29 58 [2] 2f 6d [2] 01 6d [2] 3e 71 }

  condition:
    any of them
}