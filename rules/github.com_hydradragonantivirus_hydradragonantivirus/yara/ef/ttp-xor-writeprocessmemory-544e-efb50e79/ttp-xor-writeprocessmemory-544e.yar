rule TTP_XOR_WriteProcessMemory_544e {
  strings:
    $key_544e = { 03 3c [2] 31 1e [2] 37 2b [2] 19 2b [2] 26 37 }

  condition:
    any of them
}