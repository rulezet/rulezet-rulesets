rule TTP_XOR_WriteProcessMemory_5a1b {
  strings:
    $key_5a1b = { 0d 69 [2] 3f 4b [2] 39 7e [2] 17 7e [2] 28 62 }

  condition:
    any of them
}