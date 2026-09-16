rule TTP_XOR_WriteProcessMemory_511b {
  strings:
    $key_511b = { 06 69 [2] 34 4b [2] 32 7e [2] 1c 7e [2] 23 62 }

  condition:
    any of them
}