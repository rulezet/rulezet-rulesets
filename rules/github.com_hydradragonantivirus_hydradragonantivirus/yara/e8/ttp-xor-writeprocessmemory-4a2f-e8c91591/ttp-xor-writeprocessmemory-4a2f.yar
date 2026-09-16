rule TTP_XOR_WriteProcessMemory_4a2f {
  strings:
    $key_4a2f = { 1d 5d [2] 2f 7f [2] 29 4a [2] 07 4a [2] 38 56 }

  condition:
    any of them
}