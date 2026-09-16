rule TTP_XOR_WriteProcessMemory_f33d {
  strings:
    $key_f33d = { a4 4f [2] 96 6d [2] 90 58 [2] be 58 [2] 81 44 }

  condition:
    any of them
}