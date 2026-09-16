rule TTP_XOR_WriteProcessMemory_f41f {
  strings:
    $key_f41f = { a3 6d [2] 91 4f [2] 97 7a [2] b9 7a [2] 86 66 }

  condition:
    any of them
}