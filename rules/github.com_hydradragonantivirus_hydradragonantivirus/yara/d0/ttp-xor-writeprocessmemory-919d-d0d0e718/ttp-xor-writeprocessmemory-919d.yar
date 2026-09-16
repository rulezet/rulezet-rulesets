rule TTP_XOR_WriteProcessMemory_919d {
  strings:
    $key_919d = { c6 ef [2] f4 cd [2] f2 f8 [2] dc f8 [2] e3 e4 }

  condition:
    any of them
}