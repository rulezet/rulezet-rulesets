rule TTP_XOR_WriteProcessMemory_59ff {
  strings:
    $key_59ff = { 0e 8d [2] 3c af [2] 3a 9a [2] 14 9a [2] 2b 86 }

  condition:
    any of them
}