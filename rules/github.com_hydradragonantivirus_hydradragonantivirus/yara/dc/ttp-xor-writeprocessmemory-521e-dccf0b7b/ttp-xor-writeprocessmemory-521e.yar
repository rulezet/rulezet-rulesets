rule TTP_XOR_WriteProcessMemory_521e {
  strings:
    $key_521e = { 05 6c [2] 37 4e [2] 31 7b [2] 1f 7b [2] 20 67 }

  condition:
    any of them
}