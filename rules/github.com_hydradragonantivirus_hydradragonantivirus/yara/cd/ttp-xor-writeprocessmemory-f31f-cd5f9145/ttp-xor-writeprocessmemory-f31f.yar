rule TTP_XOR_WriteProcessMemory_f31f {
  strings:
    $key_f31f = { a4 6d [2] 96 4f [2] 90 7a [2] be 7a [2] 81 66 }

  condition:
    any of them
}