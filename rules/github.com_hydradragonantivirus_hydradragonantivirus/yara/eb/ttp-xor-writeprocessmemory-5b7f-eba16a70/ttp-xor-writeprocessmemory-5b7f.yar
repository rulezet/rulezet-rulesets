rule TTP_XOR_WriteProcessMemory_5b7f {
  strings:
    $key_5b7f = { 0c 0d [2] 3e 2f [2] 38 1a [2] 16 1a [2] 29 06 }

  condition:
    any of them
}