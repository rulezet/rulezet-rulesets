rule TTP_XOR_WriteProcessMemory_720f {
  strings:
    $key_720f = { 25 7d [2] 17 5f [2] 11 6a [2] 3f 6a [2] 00 76 }

  condition:
    any of them
}