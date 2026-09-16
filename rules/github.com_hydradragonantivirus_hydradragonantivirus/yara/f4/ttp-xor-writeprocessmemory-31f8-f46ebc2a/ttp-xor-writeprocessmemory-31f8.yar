rule TTP_XOR_WriteProcessMemory_31f8 {
  strings:
    $key_31f8 = { 66 8a [2] 54 a8 [2] 52 9d [2] 7c 9d [2] 43 81 }

  condition:
    any of them
}