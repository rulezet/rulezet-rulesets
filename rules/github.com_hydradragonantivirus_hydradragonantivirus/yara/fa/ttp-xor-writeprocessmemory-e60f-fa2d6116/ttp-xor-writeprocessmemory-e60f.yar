rule TTP_XOR_WriteProcessMemory_e60f {
  strings:
    $key_e60f = { b1 7d [2] 83 5f [2] 85 6a [2] ab 6a [2] 94 76 }

  condition:
    any of them
}