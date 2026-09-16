rule TTP_XOR_WriteProcessMemory_f4dc {
  strings:
    $key_f4dc = { a3 ae [2] 91 8c [2] 97 b9 [2] b9 b9 [2] 86 a5 }

  condition:
    any of them
}