rule TTP_XOR_WriteProcessMemory_b248 {
  strings:
    $key_b248 = { e5 3a [2] d7 18 [2] d1 2d [2] ff 2d [2] c0 31 }

  condition:
    any of them
}