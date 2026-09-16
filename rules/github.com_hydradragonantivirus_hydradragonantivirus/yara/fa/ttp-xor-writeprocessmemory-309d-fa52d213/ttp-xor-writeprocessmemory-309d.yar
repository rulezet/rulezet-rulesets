rule TTP_XOR_WriteProcessMemory_309d {
  strings:
    $key_309d = { 67 ef [2] 55 cd [2] 53 f8 [2] 7d f8 [2] 42 e4 }

  condition:
    any of them
}