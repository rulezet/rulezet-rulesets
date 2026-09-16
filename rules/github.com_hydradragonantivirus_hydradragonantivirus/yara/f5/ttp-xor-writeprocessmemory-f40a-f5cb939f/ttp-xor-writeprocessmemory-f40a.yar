rule TTP_XOR_WriteProcessMemory_f40a {
  strings:
    $key_f40a = { a3 78 [2] 91 5a [2] 97 6f [2] b9 6f [2] 86 73 }

  condition:
    any of them
}