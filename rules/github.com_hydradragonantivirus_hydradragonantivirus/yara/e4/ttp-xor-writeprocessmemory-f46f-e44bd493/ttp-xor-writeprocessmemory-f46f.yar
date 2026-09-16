rule TTP_XOR_WriteProcessMemory_f46f {
  strings:
    $key_f46f = { a3 1d [2] 91 3f [2] 97 0a [2] b9 0a [2] 86 16 }

  condition:
    any of them
}