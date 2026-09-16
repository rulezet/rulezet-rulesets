rule TTP_XOR_WriteProcessMemory_e908 {
  strings:
    $key_e908 = { be 7a [2] 8c 58 [2] 8a 6d [2] a4 6d [2] 9b 71 }

  condition:
    any of them
}