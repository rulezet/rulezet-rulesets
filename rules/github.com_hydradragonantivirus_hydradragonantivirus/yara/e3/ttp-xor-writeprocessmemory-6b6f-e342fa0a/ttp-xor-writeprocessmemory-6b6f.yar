rule TTP_XOR_WriteProcessMemory_6b6f {
  strings:
    $key_6b6f = { 3c 1d [2] 0e 3f [2] 08 0a [2] 26 0a [2] 19 16 }

  condition:
    any of them
}