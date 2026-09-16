rule TTP_XOR_WriteProcessMemory_b75a {
  strings:
    $key_b75a = { e0 28 [2] d2 0a [2] d4 3f [2] fa 3f [2] c5 23 }

  condition:
    any of them
}