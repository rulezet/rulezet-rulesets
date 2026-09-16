rule TTP_XOR_WriteProcessMemory_939d {
  strings:
    $key_939d = { c4 ef [2] f6 cd [2] f0 f8 [2] de f8 [2] e1 e4 }

  condition:
    any of them
}