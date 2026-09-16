rule TTP_XOR_WriteProcessMemory_b73f {
  strings:
    $key_b73f = { e0 4d [2] d2 6f [2] d4 5a [2] fa 5a [2] c5 46 }

  condition:
    any of them
}