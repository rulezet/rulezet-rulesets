rule TTP_XOR_WriteProcessMemory_6ef8 {
  strings:
    $key_6ef8 = { 39 8a [2] 0b a8 [2] 0d 9d [2] 23 9d [2] 1c 81 }

  condition:
    any of them
}