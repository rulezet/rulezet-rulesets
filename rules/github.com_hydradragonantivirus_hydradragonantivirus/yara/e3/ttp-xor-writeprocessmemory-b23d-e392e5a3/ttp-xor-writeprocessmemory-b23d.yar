rule TTP_XOR_WriteProcessMemory_b23d {
  strings:
    $key_b23d = { e5 4f [2] d7 6d [2] d1 58 [2] ff 58 [2] c0 44 }

  condition:
    any of them
}