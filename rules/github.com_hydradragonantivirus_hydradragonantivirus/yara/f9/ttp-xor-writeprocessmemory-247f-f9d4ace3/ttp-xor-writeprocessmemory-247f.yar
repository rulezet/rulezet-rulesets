rule TTP_XOR_WriteProcessMemory_247f {
  strings:
    $key_247f = { 73 0d [2] 41 2f [2] 47 1a [2] 69 1a [2] 56 06 }

  condition:
    any of them
}