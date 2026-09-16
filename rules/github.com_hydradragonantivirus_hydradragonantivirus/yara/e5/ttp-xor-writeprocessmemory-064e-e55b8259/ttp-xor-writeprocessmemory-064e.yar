rule TTP_XOR_WriteProcessMemory_064e {
  strings:
    $key_064e = { 51 3c [2] 63 1e [2] 65 2b [2] 4b 2b [2] 74 37 }

  condition:
    any of them
}