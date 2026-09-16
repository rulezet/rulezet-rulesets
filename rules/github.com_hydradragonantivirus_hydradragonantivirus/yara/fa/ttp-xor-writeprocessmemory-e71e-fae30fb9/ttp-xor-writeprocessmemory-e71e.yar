rule TTP_XOR_WriteProcessMemory_e71e {
  strings:
    $key_e71e = { b0 6c [2] 82 4e [2] 84 7b [2] aa 7b [2] 95 67 }

  condition:
    any of them
}