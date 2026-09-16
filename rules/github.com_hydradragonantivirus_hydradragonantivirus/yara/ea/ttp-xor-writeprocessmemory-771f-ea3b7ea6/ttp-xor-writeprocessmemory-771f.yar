rule TTP_XOR_WriteProcessMemory_771f {
  strings:
    $key_771f = { 20 6d [2] 12 4f [2] 14 7a [2] 3a 7a [2] 05 66 }

  condition:
    any of them
}