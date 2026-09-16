rule TTP_XOR_WriteProcessMemory_377f {
  strings:
    $key_377f = { 60 0d [2] 52 2f [2] 54 1a [2] 7a 1a [2] 45 06 }

  condition:
    any of them
}