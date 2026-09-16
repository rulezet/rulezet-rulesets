rule TTP_XOR_WriteProcessMemory_603f {
  strings:
    $key_603f = { 37 4d [2] 05 6f [2] 03 5a [2] 2d 5a [2] 12 46 }

  condition:
    any of them
}