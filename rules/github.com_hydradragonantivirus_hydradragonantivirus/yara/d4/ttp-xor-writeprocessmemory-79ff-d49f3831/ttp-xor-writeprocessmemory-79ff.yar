rule TTP_XOR_WriteProcessMemory_79ff {
  strings:
    $key_79ff = { 2e 8d [2] 1c af [2] 1a 9a [2] 34 9a [2] 0b 86 }

  condition:
    any of them
}