rule TTP_XOR_WriteProcessMemory_b255 {
  strings:
    $key_b255 = { e5 27 [2] d7 05 [2] d1 30 [2] ff 30 [2] c0 2c }

  condition:
    any of them
}