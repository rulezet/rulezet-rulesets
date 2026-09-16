rule TTP_XOR_WriteProcessMemory_442f {
  strings:
    $key_442f = { 13 5d [2] 21 7f [2] 27 4a [2] 09 4a [2] 36 56 }

  condition:
    any of them
}