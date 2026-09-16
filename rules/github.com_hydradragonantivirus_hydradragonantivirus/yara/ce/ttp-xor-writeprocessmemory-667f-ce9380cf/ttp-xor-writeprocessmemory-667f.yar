rule TTP_XOR_WriteProcessMemory_667f {
  strings:
    $key_667f = { 31 0d [2] 03 2f [2] 05 1a [2] 2b 1a [2] 14 06 }

  condition:
    any of them
}