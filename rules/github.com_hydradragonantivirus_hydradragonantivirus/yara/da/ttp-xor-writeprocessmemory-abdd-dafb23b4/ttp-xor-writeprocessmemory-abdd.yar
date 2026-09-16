rule TTP_XOR_WriteProcessMemory_abdd {
  strings:
    $key_abdd = { fc af [2] ce 8d [2] c8 b8 [2] e6 b8 [2] d9 a4 }

  condition:
    any of them
}