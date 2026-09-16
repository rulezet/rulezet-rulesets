rule TTP_XOR_WriteProcessMemory_e63f {
  strings:
    $key_e63f = { b1 4d [2] 83 6f [2] 85 5a [2] ab 5a [2] 94 46 }

  condition:
    any of them
}