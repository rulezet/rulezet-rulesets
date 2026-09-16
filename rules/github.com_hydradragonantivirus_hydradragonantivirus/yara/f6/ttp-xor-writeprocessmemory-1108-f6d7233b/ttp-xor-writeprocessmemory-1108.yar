rule TTP_XOR_WriteProcessMemory_1108 {
  strings:
    $key_1108 = { 46 7a [2] 74 58 [2] 72 6d [2] 5c 6d [2] 63 71 }

  condition:
    any of them
}