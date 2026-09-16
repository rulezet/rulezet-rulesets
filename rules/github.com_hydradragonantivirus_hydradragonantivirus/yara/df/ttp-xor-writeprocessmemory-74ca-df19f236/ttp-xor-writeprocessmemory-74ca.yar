rule TTP_XOR_WriteProcessMemory_74ca {
  strings:
    $key_74ca = { 23 b8 [2] 11 9a [2] 17 af [2] 39 af [2] 06 b3 }

  condition:
    any of them
}