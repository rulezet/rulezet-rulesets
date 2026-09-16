rule TTP_XOR_WriteProcessMemory_f51e {
  strings:
    $key_f51e = { a2 6c [2] 90 4e [2] 96 7b [2] b8 7b [2] 87 67 }

  condition:
    any of them
}