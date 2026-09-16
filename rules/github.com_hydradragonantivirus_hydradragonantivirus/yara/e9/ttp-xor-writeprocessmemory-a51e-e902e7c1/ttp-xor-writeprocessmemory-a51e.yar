rule TTP_XOR_WriteProcessMemory_a51e {
  strings:
    $key_a51e = { f2 6c [2] c0 4e [2] c6 7b [2] e8 7b [2] d7 67 }

  condition:
    any of them
}