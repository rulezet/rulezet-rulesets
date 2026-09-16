rule TTP_XOR_WriteProcessMemory_daf8 {
  strings:
    $key_daf8 = { 8d 8a [2] bf a8 [2] b9 9d [2] 97 9d [2] a8 81 }

  condition:
    any of them
}