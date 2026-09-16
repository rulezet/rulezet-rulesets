rule TTP_XOR_WriteProcessMemory_f48a {
  strings:
    $key_f48a = { a3 f8 [2] 91 da [2] 97 ef [2] b9 ef [2] 86 f3 }

  condition:
    any of them
}