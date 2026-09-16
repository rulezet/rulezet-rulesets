rule TTP_XOR_WriteProcessMemory_a0ca {
  strings:
    $key_a0ca = { f7 b8 [2] c5 9a [2] c3 af [2] ed af [2] d2 b3 }

  condition:
    any of them
}