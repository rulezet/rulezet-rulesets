rule TTP_XOR_WriteProcessMemory_b252 {
  strings:
    $key_b252 = { e5 20 [2] d7 02 [2] d1 37 [2] ff 37 [2] c0 2b }

  condition:
    any of them
}