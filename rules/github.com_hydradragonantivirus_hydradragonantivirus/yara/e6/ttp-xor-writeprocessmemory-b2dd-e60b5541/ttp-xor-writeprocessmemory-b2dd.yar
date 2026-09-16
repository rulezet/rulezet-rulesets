rule TTP_XOR_WriteProcessMemory_b2dd {
  strings:
    $key_b2dd = { e5 af [2] d7 8d [2] d1 b8 [2] ff b8 [2] c0 a4 }

  condition:
    any of them
}