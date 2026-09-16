rule TTP_XOR_WriteProcessMemory_2ef8 {
  strings:
    $key_2ef8 = { 79 8a [2] 4b a8 [2] 4d 9d [2] 63 9d [2] 5c 81 }

  condition:
    any of them
}