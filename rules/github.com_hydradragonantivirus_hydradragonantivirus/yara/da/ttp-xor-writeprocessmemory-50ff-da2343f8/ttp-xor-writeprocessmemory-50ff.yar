rule TTP_XOR_WriteProcessMemory_50ff {
  strings:
    $key_50ff = { 07 8d [2] 35 af [2] 33 9a [2] 1d 9a [2] 22 86 }

  condition:
    any of them
}