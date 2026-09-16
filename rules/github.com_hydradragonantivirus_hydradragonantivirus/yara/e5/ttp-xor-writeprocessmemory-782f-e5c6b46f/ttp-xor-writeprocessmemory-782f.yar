rule TTP_XOR_WriteProcessMemory_782f {
  strings:
    $key_782f = { 2f 5d [2] 1d 7f [2] 1b 4a [2] 35 4a [2] 0a 56 }

  condition:
    any of them
}