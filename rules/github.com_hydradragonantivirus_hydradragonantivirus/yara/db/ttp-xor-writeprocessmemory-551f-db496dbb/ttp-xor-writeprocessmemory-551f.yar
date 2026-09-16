rule TTP_XOR_WriteProcessMemory_551f {
  strings:
    $key_551f = { 02 6d [2] 30 4f [2] 36 7a [2] 18 7a [2] 27 66 }

  condition:
    any of them
}