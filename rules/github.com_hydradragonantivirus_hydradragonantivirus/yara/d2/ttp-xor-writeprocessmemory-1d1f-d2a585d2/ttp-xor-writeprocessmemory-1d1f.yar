rule TTP_XOR_WriteProcessMemory_1d1f {
  strings:
    $key_1d1f = { 4a 6d [2] 78 4f [2] 7e 7a [2] 50 7a [2] 6f 66 }

  condition:
    any of them
}