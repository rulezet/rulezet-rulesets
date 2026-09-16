rule TTP_XOR_WriteProcessMemory_307f {
  strings:
    $key_307f = { 67 0d [2] 55 2f [2] 53 1a [2] 7d 1a [2] 42 06 }

  condition:
    any of them
}