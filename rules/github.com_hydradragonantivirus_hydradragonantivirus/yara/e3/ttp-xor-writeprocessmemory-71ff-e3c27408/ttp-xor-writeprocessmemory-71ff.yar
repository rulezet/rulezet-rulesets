rule TTP_XOR_WriteProcessMemory_71ff {
  strings:
    $key_71ff = { 26 8d [2] 14 af [2] 12 9a [2] 3c 9a [2] 03 86 }

  condition:
    any of them
}