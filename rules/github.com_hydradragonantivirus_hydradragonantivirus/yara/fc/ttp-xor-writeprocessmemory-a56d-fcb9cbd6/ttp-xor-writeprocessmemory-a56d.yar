rule TTP_XOR_WriteProcessMemory_a56d {
  strings:
    $key_a56d = { f2 1f [2] c0 3d [2] c6 08 [2] e8 08 [2] d7 14 }

  condition:
    any of them
}