rule TTP_XOR_WriteProcessMemory_006f {
  strings:
    $key_006f = { 57 1d [2] 65 3f [2] 63 0a [2] 4d 0a [2] 72 16 }

  condition:
    any of them
}