rule TTP_XOR_WriteProcessMemory_7ab4 {
  strings:
    $key_7ab4 = { 2d c6 [2] 1f e4 [2] 19 d1 [2] 37 d1 [2] 08 cd }

  condition:
    any of them
}