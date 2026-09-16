rule TTP_XOR_WriteProcessMemory_0cf8 {
  strings:
    $key_0cf8 = { 5b 8a [2] 69 a8 [2] 6f 9d [2] 41 9d [2] 7e 81 }

  condition:
    any of them
}