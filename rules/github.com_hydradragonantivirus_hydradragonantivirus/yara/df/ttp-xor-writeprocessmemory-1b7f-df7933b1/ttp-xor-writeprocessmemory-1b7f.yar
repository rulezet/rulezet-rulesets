rule TTP_XOR_WriteProcessMemory_1b7f {
  strings:
    $key_1b7f = { 4c 0d [2] 7e 2f [2] 78 1a [2] 56 1a [2] 69 06 }

  condition:
    any of them
}