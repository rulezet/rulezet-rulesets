rule TTP_XOR_WriteProcessMemory_5428 {
  strings:
    $key_5428 = { 03 5a [2] 31 78 [2] 37 4d [2] 19 4d [2] 26 51 }

  condition:
    any of them
}