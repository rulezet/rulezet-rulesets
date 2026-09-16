rule TTP_XOR_WriteProcessMemory_f308 {
  strings:
    $key_f308 = { a4 7a [2] 96 58 [2] 90 6d [2] be 6d [2] 81 71 }

  condition:
    any of them
}