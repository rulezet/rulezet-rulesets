rule TTP_XOR_WriteProcessMemory_2ff8 {
  strings:
    $key_2ff8 = { 78 8a [2] 4a a8 [2] 4c 9d [2] 62 9d [2] 5d 81 }

  condition:
    any of them
}