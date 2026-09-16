rule TTP_XOR_WriteProcessMemory_f2ca {
  strings:
    $key_f2ca = { a5 b8 [2] 97 9a [2] 91 af [2] bf af [2] 80 b3 }

  condition:
    any of them
}