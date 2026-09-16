rule TTP_XOR_WriteProcessMemory_f408 {
  strings:
    $key_f408 = { a3 7a [2] 91 58 [2] 97 6d [2] b9 6d [2] 86 71 }

  condition:
    any of them
}