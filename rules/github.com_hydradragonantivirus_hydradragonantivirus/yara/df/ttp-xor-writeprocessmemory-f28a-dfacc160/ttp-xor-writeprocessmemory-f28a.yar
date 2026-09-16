rule TTP_XOR_WriteProcessMemory_f28a {
  strings:
    $key_f28a = { a5 f8 [2] 97 da [2] 91 ef [2] bf ef [2] 80 f3 }

  condition:
    any of them
}