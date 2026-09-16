rule TTP_XOR_WriteProcessMemory_6f08 {
  strings:
    $key_6f08 = { 38 7a [2] 0a 58 [2] 0c 6d [2] 22 6d [2] 1d 71 }

  condition:
    any of them
}