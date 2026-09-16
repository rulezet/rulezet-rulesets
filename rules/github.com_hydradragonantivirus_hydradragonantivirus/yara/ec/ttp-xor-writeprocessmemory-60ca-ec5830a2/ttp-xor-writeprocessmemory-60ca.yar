rule TTP_XOR_WriteProcessMemory_60ca {
  strings:
    $key_60ca = { 37 b8 [2] 05 9a [2] 03 af [2] 2d af [2] 12 b3 }

  condition:
    any of them
}