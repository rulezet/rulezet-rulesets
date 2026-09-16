rule TTP_XOR_WriteProcessMemory_a51d {
  strings:
    $key_a51d = { f2 6f [2] c0 4d [2] c6 78 [2] e8 78 [2] d7 64 }

  condition:
    any of them
}