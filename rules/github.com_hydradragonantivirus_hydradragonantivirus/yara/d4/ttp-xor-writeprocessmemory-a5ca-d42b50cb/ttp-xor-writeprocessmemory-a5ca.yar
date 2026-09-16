rule TTP_XOR_WriteProcessMemory_a5ca {
  strings:
    $key_a5ca = { f2 b8 [2] c0 9a [2] c6 af [2] e8 af [2] d7 b3 }

  condition:
    any of them
}