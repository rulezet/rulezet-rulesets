rule TTP_XOR_WriteProcessMemory_6cf8 {
  strings:
    $key_6cf8 = { 3b 8a [2] 09 a8 [2] 0f 9d [2] 21 9d [2] 1e 81 }

  condition:
    any of them
}