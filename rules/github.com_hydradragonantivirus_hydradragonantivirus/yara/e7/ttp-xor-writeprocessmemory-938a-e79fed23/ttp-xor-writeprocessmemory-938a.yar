rule TTP_XOR_WriteProcessMemory_938a {
  strings:
    $key_938a = { c4 f8 [2] f6 da [2] f0 ef [2] de ef [2] e1 f3 }

  condition:
    any of them
}