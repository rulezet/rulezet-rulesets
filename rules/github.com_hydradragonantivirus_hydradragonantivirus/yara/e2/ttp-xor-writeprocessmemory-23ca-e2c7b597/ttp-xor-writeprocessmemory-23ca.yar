rule TTP_XOR_WriteProcessMemory_23ca {
  strings:
    $key_23ca = { 74 b8 [2] 46 9a [2] 40 af [2] 6e af [2] 51 b3 }

  condition:
    any of them
}