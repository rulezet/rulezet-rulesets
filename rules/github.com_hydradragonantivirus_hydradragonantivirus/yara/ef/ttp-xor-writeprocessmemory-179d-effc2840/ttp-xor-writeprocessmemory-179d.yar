rule TTP_XOR_WriteProcessMemory_179d {
  strings:
    $key_179d = { 40 ef [2] 72 cd [2] 74 f8 [2] 5a f8 [2] 65 e4 }

  condition:
    any of them
}