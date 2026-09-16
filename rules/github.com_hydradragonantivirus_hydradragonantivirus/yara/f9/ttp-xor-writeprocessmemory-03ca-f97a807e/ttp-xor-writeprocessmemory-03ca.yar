rule TTP_XOR_WriteProcessMemory_03ca {
  strings:
    $key_03ca = { 54 b8 [2] 66 9a [2] 60 af [2] 4e af [2] 71 b3 }

  condition:
    any of them
}