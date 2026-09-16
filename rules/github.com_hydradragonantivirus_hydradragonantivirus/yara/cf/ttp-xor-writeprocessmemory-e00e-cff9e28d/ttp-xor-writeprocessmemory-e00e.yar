rule TTP_XOR_WriteProcessMemory_e00e {
  strings:
    $key_e00e = { b7 7c [2] 85 5e [2] 83 6b [2] ad 6b [2] 92 77 }

  condition:
    any of them
}