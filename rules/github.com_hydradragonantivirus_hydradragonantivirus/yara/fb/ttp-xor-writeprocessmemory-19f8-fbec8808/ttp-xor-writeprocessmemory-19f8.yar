rule TTP_XOR_WriteProcessMemory_19f8 {
  strings:
    $key_19f8 = { 4e 8a [2] 7c a8 [2] 7a 9d [2] 54 9d [2] 6b 81 }

  condition:
    any of them
}