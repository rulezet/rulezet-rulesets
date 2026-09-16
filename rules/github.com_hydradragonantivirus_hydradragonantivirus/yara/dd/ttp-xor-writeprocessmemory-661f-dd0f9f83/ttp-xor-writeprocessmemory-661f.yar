rule TTP_XOR_WriteProcessMemory_661f {
  strings:
    $key_661f = { 31 6d [2] 03 4f [2] 05 7a [2] 2b 7a [2] 14 66 }

  condition:
    any of them
}