rule TTP_XOR_WriteProcessMemory_141b {
  strings:
    $key_141b = { 43 69 [2] 71 4b [2] 77 7e [2] 59 7e [2] 66 62 }

  condition:
    any of them
}