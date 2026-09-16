rule TTP_XOR_WriteProcessMemory_45f8 {
  strings:
    $key_45f8 = { 12 8a [2] 20 a8 [2] 26 9d [2] 08 9d [2] 37 81 }

  condition:
    any of them
}