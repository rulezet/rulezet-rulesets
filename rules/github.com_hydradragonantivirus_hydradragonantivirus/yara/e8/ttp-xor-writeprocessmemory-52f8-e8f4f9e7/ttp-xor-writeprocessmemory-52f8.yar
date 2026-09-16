rule TTP_XOR_WriteProcessMemory_52f8 {
  strings:
    $key_52f8 = { 05 8a [2] 37 a8 [2] 31 9d [2] 1f 9d [2] 20 81 }

  condition:
    any of them
}