rule TTP_XOR_WriteProcessMemory_f3ca {
  strings:
    $key_f3ca = { a4 b8 [2] 96 9a [2] 90 af [2] be af [2] 81 b3 }

  condition:
    any of them
}