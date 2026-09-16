rule TTP_XOR_WriteProcessMemory_fef8 {
  strings:
    $key_fef8 = { a9 8a [2] 9b a8 [2] 9d 9d [2] b3 9d [2] 8c 81 }

  condition:
    any of them
}