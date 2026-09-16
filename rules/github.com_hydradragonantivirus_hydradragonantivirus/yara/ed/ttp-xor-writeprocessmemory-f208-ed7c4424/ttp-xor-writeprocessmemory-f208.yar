rule TTP_XOR_WriteProcessMemory_f208 {
  strings:
    $key_f208 = { a5 7a [2] 97 58 [2] 91 6d [2] bf 6d [2] 80 71 }

  condition:
    any of them
}