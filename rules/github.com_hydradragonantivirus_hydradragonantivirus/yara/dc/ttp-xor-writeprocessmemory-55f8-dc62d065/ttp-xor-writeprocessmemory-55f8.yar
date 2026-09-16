rule TTP_XOR_WriteProcessMemory_55f8 {
  strings:
    $key_55f8 = { 02 8a [2] 30 a8 [2] 36 9d [2] 18 9d [2] 27 81 }

  condition:
    any of them
}