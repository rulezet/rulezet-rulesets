rule TTP_XOR_WriteProcessMemory_597f {
  strings:
    $key_597f = { 0e 0d [2] 3c 2f [2] 3a 1a [2] 14 1a [2] 2b 06 }

  condition:
    any of them
}