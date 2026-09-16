rule TTP_XOR_WriteProcessMemory_66ff {
  strings:
    $key_66ff = { 31 8d [2] 03 af [2] 05 9a [2] 2b 9a [2] 14 86 }

  condition:
    any of them
}