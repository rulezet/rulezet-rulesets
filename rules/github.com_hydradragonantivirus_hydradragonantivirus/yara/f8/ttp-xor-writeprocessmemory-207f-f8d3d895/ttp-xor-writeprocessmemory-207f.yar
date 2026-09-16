rule TTP_XOR_WriteProcessMemory_207f {
  strings:
    $key_207f = { 77 0d [2] 45 2f [2] 43 1a [2] 6d 1a [2] 52 06 }

  condition:
    any of them
}