rule TTP_XOR_WriteProcessMemory_0ef8 {
  strings:
    $key_0ef8 = { 59 8a [2] 6b a8 [2] 6d 9d [2] 43 9d [2] 7c 81 }

  condition:
    any of them
}