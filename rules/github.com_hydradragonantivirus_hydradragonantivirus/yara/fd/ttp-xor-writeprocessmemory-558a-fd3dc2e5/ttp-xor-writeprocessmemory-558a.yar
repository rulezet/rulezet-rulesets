rule TTP_XOR_WriteProcessMemory_558a {
  strings:
    $key_558a = { 02 f8 [2] 30 da [2] 36 ef [2] 18 ef [2] 27 f3 }

  condition:
    any of them
}