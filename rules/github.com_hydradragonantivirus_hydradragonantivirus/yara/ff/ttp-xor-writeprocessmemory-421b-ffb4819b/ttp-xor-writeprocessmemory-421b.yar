rule TTP_XOR_WriteProcessMemory_421b {
  strings:
    $key_421b = { 15 69 [2] 27 4b [2] 21 7e [2] 0f 7e [2] 30 62 }

  condition:
    any of them
}