rule TTP_XOR_WriteProcessMemory_613f {
  strings:
    $key_613f = { 36 4d [2] 04 6f [2] 02 5a [2] 2c 5a [2] 13 46 }

  condition:
    any of them
}