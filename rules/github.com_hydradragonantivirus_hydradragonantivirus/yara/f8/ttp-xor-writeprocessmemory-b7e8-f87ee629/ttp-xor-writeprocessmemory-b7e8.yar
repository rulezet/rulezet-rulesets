rule TTP_XOR_WriteProcessMemory_b7e8 {
  strings:
    $key_b7e8 = { e0 9a [2] d2 b8 [2] d4 8d [2] fa 8d [2] c5 91 }

  condition:
    any of them
}