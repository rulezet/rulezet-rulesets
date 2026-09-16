rule TTP_XOR_WriteProcessMemory_158a {
  strings:
    $key_158a = { 42 f8 [2] 70 da [2] 76 ef [2] 58 ef [2] 67 f3 }

  condition:
    any of them
}