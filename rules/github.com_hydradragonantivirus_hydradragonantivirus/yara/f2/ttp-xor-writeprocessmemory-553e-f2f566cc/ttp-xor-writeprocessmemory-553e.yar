rule TTP_XOR_WriteProcessMemory_553e {
  strings:
    $key_553e = { 02 4c [2] 30 6e [2] 36 5b [2] 18 5b [2] 27 47 }

  condition:
    any of them
}