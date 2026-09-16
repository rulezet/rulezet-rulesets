rule TTP_XOR_WriteProcessMemory_10f8 {
  strings:
    $key_10f8 = { 47 8a [2] 75 a8 [2] 73 9d [2] 5d 9d [2] 62 81 }

  condition:
    any of them
}