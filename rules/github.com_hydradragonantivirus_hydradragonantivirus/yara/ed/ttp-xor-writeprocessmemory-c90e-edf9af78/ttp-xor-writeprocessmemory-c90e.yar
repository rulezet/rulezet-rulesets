rule TTP_XOR_WriteProcessMemory_c90e {
  strings:
    $key_c90e = { 9e 7c [2] ac 5e [2] aa 6b [2] 84 6b [2] bb 77 }

  condition:
    any of them
}