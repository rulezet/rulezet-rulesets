rule TTP_XOR_WriteProcessMemory_78ca {
  strings:
    $key_78ca = { 2f b8 [2] 1d 9a [2] 1b af [2] 35 af [2] 0a b3 }

  condition:
    any of them
}