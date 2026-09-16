rule TTP_XOR_WriteProcessMemory_3ff8 {
  strings:
    $key_3ff8 = { 68 8a [2] 5a a8 [2] 5c 9d [2] 72 9d [2] 4d 81 }

  condition:
    any of them
}