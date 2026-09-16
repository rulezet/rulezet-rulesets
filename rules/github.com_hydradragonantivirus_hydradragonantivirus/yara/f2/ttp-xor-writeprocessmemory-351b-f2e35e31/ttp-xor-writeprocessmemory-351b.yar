rule TTP_XOR_WriteProcessMemory_351b {
  strings:
    $key_351b = { 62 69 [2] 50 4b [2] 56 7e [2] 78 7e [2] 47 62 }

  condition:
    any of them
}