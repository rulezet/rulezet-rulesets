rule TTP_XOR_WriteProcessMemory_1068 {
  strings:
    $key_1068 = { 47 1a [2] 75 38 [2] 73 0d [2] 5d 0d [2] 62 11 }

  condition:
    any of them
}