rule TTP_XOR_WriteProcessMemory_d8ff {
  strings:
    $key_d8ff = { 8f 8d [2] bd af [2] bb 9a [2] 95 9a [2] aa 86 }

  condition:
    any of them
}