rule TTP_XOR_WriteProcessMemory_431f {
  strings:
    $key_431f = { 14 6d [2] 26 4f [2] 20 7a [2] 0e 7a [2] 31 66 }

  condition:
    any of them
}