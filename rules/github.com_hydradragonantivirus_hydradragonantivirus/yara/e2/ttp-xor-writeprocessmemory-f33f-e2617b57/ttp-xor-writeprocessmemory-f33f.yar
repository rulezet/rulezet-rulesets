rule TTP_XOR_WriteProcessMemory_f33f {
  strings:
    $key_f33f = { a4 4d [2] 96 6f [2] 90 5a [2] be 5a [2] 81 46 }

  condition:
    any of them
}