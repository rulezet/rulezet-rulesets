rule TTP_XOR_WriteProcessMemory_537d {
  strings:
    $key_537d = { 04 0f [2] 36 2d [2] 30 18 [2] 1e 18 [2] 21 04 }

  condition:
    any of them
}