rule TTP_XOR_WriteProcessMemory_f37c {
  strings:
    $key_f37c = { a4 0e [2] 96 2c [2] 90 19 [2] be 19 [2] 81 05 }

  condition:
    any of them
}