rule TTP_XOR_WriteProcessMemory_3df8 {
  strings:
    $key_3df8 = { 6a 8a [2] 58 a8 [2] 5e 9d [2] 70 9d [2] 4f 81 }

  condition:
    any of them
}