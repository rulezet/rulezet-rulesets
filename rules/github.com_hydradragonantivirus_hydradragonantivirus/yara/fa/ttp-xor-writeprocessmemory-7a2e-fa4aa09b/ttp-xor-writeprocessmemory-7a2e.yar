rule TTP_XOR_WriteProcessMemory_7a2e {
  strings:
    $key_7a2e = { 2d 5c [2] 1f 7e [2] 19 4b [2] 37 4b [2] 08 57 }

  condition:
    any of them
}