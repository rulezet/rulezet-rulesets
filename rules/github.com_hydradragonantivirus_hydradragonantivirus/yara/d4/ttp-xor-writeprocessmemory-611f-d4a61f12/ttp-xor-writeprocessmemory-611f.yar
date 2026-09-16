rule TTP_XOR_WriteProcessMemory_611f {
  strings:
    $key_611f = { 36 6d [2] 04 4f [2] 02 7a [2] 2c 7a [2] 13 66 }

  condition:
    any of them
}