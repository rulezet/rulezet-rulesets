rule TTP_XOR_WriteProcessMemory_7ef8 {
  strings:
    $key_7ef8 = { 29 8a [2] 1b a8 [2] 1d 9d [2] 33 9d [2] 0c 81 }

  condition:
    any of them
}