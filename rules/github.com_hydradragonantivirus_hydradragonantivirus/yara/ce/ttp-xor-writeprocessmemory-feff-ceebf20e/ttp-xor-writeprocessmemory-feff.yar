rule TTP_XOR_WriteProcessMemory_feff {
  strings:
    $key_feff = { a9 8d [2] 9b af [2] 9d 9a [2] b3 9a [2] 8c 86 }

  condition:
    any of them
}