rule TTP_XOR_WriteProcessMemory_7aa4 {
  strings:
    $key_7aa4 = { 2d d6 [2] 1f f4 [2] 19 c1 [2] 37 c1 [2] 08 dd }

  condition:
    any of them
}