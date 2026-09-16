rule TTP_XOR_WriteProcessMemory_1df8 {
  strings:
    $key_1df8 = { 4a 8a [2] 78 a8 [2] 7e 9d [2] 50 9d [2] 6f 81 }

  condition:
    any of them
}