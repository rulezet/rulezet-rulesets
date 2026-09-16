rule TTP_XOR_WriteProcessMemory_f4e8 {
  strings:
    $key_f4e8 = { a3 9a [2] 91 b8 [2] 97 8d [2] b9 8d [2] 86 91 }

  condition:
    any of them
}