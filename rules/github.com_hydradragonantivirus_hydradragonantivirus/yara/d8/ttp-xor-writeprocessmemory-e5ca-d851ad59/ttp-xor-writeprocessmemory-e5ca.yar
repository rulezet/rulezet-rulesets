rule TTP_XOR_WriteProcessMemory_e5ca {
  strings:
    $key_e5ca = { b2 b8 [2] 80 9a [2] 86 af [2] a8 af [2] 97 b3 }

  condition:
    any of them
}