rule TTP_XOR_WriteProcessMemory_ed2d {
  strings:
    $key_ed2d = { ba 5f [2] 88 7d [2] 8e 48 [2] a0 48 [2] 9f 54 }

  condition:
    any of them
}