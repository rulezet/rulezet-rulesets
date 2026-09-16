rule TTP_XOR_WriteProcessMemory_77ff {
  strings:
    $key_77ff = { 20 8d [2] 12 af [2] 14 9a [2] 3a 9a [2] 05 86 }

  condition:
    any of them
}