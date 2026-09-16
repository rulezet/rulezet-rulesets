rule TTP_XOR_WriteProcessMemory_daeb {
  strings:
    $key_daeb = { 8d 99 [2] bf bb [2] b9 8e [2] 97 8e [2] a8 92 }

  condition:
    any of them
}