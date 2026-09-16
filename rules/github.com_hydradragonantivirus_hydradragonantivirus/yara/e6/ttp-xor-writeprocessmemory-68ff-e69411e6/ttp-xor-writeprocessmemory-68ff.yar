rule TTP_XOR_WriteProcessMemory_68ff {
  strings:
    $key_68ff = { 3f 8d [2] 0d af [2] 0b 9a [2] 25 9a [2] 1a 86 }

  condition:
    any of them
}