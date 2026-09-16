rule TTP_XOR_WriteProcessMemory_7e08 {
  strings:
    $key_7e08 = { 29 7a [2] 1b 58 [2] 1d 6d [2] 33 6d [2] 0c 71 }

  condition:
    any of them
}