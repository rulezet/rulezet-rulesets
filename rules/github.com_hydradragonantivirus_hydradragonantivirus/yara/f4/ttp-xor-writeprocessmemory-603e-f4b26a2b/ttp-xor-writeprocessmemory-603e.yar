rule TTP_XOR_WriteProcessMemory_603e {
  strings:
    $key_603e = { 37 4c [2] 05 6e [2] 03 5b [2] 2d 5b [2] 12 47 }

  condition:
    any of them
}