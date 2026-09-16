rule TTP_XOR_WriteProcessMemory_5fca {
  strings:
    $key_5fca = { 08 b8 [2] 3a 9a [2] 3c af [2] 12 af [2] 2d b3 }

  condition:
    any of them
}