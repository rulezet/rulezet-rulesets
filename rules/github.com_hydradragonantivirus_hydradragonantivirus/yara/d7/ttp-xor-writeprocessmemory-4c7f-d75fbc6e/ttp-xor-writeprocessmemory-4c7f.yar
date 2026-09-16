rule TTP_XOR_WriteProcessMemory_4c7f {
  strings:
    $key_4c7f = { 1b 0d [2] 29 2f [2] 2f 1a [2] 01 1a [2] 3e 06 }

  condition:
    any of them
}