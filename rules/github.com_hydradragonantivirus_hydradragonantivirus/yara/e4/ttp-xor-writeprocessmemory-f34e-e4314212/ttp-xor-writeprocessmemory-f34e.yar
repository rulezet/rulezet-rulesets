rule TTP_XOR_WriteProcessMemory_f34e {
  strings:
    $key_f34e = { a4 3c [2] 96 1e [2] 90 2b [2] be 2b [2] 81 37 }

  condition:
    any of them
}