rule TTP_XOR_WriteProcessMemory_539d {
  strings:
    $key_539d = { 04 ef [2] 36 cd [2] 30 f8 [2] 1e f8 [2] 21 e4 }

  condition:
    any of them
}