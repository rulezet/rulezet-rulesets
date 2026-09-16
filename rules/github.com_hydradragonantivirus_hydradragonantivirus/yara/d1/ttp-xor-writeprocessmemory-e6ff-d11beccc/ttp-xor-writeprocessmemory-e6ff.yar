rule TTP_XOR_WriteProcessMemory_e6ff {
  strings:
    $key_e6ff = { b1 8d [2] 83 af [2] 85 9a [2] ab 9a [2] 94 86 }

  condition:
    any of them
}