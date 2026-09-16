rule TTP_XOR_WriteProcessMemory_f44a {
  strings:
    $key_f44a = { a3 38 [2] 91 1a [2] 97 2f [2] b9 2f [2] 86 33 }

  condition:
    any of them
}