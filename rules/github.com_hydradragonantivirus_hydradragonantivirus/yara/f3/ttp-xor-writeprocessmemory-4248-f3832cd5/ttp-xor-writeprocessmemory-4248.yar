rule TTP_XOR_WriteProcessMemory_4248 {
  strings:
    $key_4248 = { 15 3a [2] 27 18 [2] 21 2d [2] 0f 2d [2] 30 31 }

  condition:
    any of them
}