rule TTP_XOR_WriteProcessMemory_ed4d {
  strings:
    $key_ed4d = { ba 3f [2] 88 1d [2] 8e 28 [2] a0 28 [2] 9f 34 }

  condition:
    any of them
}