rule TTP_XOR_WriteProcessMemory_68ca {
  strings:
    $key_68ca = { 3f b8 [2] 0d 9a [2] 0b af [2] 25 af [2] 1a b3 }

  condition:
    any of them
}