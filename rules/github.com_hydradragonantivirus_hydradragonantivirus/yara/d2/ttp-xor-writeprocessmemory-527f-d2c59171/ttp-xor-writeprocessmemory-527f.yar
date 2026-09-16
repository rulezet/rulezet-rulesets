rule TTP_XOR_WriteProcessMemory_527f {
  strings:
    $key_527f = { 05 0d [2] 37 2f [2] 31 1a [2] 1f 1a [2] 20 06 }

  condition:
    any of them
}