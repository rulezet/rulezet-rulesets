rule TTP_XOR_WriteProcessMemory_622f {
  strings:
    $key_622f = { 35 5d [2] 07 7f [2] 01 4a [2] 2f 4a [2] 10 56 }

  condition:
    any of them
}