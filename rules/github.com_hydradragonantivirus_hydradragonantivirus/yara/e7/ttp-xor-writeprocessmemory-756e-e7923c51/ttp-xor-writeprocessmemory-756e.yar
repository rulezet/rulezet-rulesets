rule TTP_XOR_WriteProcessMemory_756e {
  strings:
    $key_756e = { 22 1c [2] 10 3e [2] 16 0b [2] 38 0b [2] 07 17 }

  condition:
    any of them
}