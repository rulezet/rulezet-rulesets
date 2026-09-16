rule TTP_XOR_WriteProcessMemory_4d1f {
  strings:
    $key_4d1f = { 1a 6d [2] 28 4f [2] 2e 7a [2] 00 7a [2] 3f 66 }

  condition:
    any of them
}