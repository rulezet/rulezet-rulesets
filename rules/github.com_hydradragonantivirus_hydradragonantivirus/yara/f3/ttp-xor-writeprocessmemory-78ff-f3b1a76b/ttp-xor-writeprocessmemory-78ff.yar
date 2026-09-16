rule TTP_XOR_WriteProcessMemory_78ff {
  strings:
    $key_78ff = { 2f 8d [2] 1d af [2] 1b 9a [2] 35 9a [2] 0a 86 }

  condition:
    any of them
}