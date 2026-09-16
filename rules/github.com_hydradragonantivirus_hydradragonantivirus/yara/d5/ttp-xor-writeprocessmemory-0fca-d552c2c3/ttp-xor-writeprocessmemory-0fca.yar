rule TTP_XOR_WriteProcessMemory_0fca {
  strings:
    $key_0fca = { 58 b8 [2] 6a 9a [2] 6c af [2] 42 af [2] 7d b3 }

  condition:
    any of them
}