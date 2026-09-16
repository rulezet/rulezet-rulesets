rule TTP_XOR_WriteProcessMemory_542e {
  strings:
    $key_542e = { 03 5c [2] 31 7e [2] 37 4b [2] 19 4b [2] 26 57 }

  condition:
    any of them
}