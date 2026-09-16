rule TTP_XOR_WriteProcessMemory_f36c {
  strings:
    $key_f36c = { a4 1e [2] 96 3c [2] 90 09 [2] be 09 [2] 81 15 }

  condition:
    any of them
}