rule TTP_XOR_WriteProcessMemory_f33c {
  strings:
    $key_f33c = { a4 4e [2] 96 6c [2] 90 59 [2] be 59 [2] 81 45 }

  condition:
    any of them
}