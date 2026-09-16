rule TTP_XOR_WriteProcessMemory_3408 {
  strings:
    $key_3408 = { 63 7a [2] 51 58 [2] 57 6d [2] 79 6d [2] 46 71 }

  condition:
    any of them
}