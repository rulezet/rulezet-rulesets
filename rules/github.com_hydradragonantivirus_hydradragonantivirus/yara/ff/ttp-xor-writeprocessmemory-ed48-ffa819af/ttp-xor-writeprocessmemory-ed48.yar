rule TTP_XOR_WriteProcessMemory_ed48 {
  strings:
    $key_ed48 = { ba 3a [2] 88 18 [2] 8e 2d [2] a0 2d [2] 9f 31 }

  condition:
    any of them
}