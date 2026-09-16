rule TTP_XOR_WriteProcessMemory_b71e {
  strings:
    $key_b71e = { e0 6c [2] d2 4e [2] d4 7b [2] fa 7b [2] c5 67 }

  condition:
    any of them
}