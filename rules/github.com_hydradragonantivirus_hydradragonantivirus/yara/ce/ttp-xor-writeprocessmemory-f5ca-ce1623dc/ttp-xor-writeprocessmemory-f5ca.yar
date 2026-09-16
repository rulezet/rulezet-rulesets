rule TTP_XOR_WriteProcessMemory_f5ca {
  strings:
    $key_f5ca = { a2 b8 [2] 90 9a [2] 96 af [2] b8 af [2] 87 b3 }

  condition:
    any of them
}