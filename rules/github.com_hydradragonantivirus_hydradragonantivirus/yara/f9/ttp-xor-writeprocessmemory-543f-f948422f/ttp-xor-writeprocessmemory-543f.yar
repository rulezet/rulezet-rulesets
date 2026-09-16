rule TTP_XOR_WriteProcessMemory_543f {
  strings:
    $key_543f = { 03 4d [2] 31 6f [2] 37 5a [2] 19 5a [2] 26 46 }

  condition:
    any of them
}