rule TTP_XOR_WriteProcessMemory_ee91 {
  strings:
    $key_ee91 = { b9 e3 [2] 8b c1 [2] 8d f4 [2] a3 f4 [2] 9c e8 }

  condition:
    any of them
}