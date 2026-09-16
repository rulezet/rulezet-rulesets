rule TTP_XOR_WriteProcessMemory_838a {
  strings:
    $key_838a = { d4 f8 [2] e6 da [2] e0 ef [2] ce ef [2] f1 f3 }

  condition:
    any of them
}