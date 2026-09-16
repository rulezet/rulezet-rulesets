rule TTP_XOR_WriteProcessMemory_b2bb {
  strings:
    $key_b2bb = { e5 c9 [2] d7 eb [2] d1 de [2] ff de [2] c0 c2 }

  condition:
    any of them
}