rule TTP_XOR_WriteProcessMemory_218a {
  strings:
    $key_218a = { 76 f8 [2] 44 da [2] 42 ef [2] 6c ef [2] 53 f3 }

  condition:
    any of them
}