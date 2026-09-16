rule TTP_XOR_WriteProcessMemory_82bf {
  strings:
    $key_82bf = { d5 cd [2] e7 ef [2] e1 da [2] cf da [2] f0 c6 }

  condition:
    any of them
}