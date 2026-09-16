rule TTP_XOR_WriteProcessMemory_147e {
  strings:
    $key_147e = { 43 0c [2] 71 2e [2] 77 1b [2] 59 1b [2] 66 07 }

  condition:
    any of them
}