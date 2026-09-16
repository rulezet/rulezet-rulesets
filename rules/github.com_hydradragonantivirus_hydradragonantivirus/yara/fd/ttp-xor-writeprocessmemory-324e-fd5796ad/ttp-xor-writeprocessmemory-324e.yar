rule TTP_XOR_WriteProcessMemory_324e {
  strings:
    $key_324e = { 65 3c [2] 57 1e [2] 51 2b [2] 7f 2b [2] 40 37 }

  condition:
    any of them
}