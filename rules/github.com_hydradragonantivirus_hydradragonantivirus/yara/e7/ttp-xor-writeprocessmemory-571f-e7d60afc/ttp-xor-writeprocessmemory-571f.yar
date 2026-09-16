rule TTP_XOR_WriteProcessMemory_571f {
  strings:
    $key_571f = { 00 6d [2] 32 4f [2] 34 7a [2] 1a 7a [2] 25 66 }

  condition:
    any of them
}