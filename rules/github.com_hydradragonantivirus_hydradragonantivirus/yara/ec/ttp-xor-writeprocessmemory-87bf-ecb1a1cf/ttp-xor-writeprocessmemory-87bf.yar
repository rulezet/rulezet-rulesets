rule TTP_XOR_WriteProcessMemory_87bf {
  strings:
    $key_87bf = { d0 cd [2] e2 ef [2] e4 da [2] ca da [2] f5 c6 }

  condition:
    any of them
}