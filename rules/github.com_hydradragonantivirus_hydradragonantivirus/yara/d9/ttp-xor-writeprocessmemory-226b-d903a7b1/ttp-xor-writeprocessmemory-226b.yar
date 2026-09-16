rule TTP_XOR_WriteProcessMemory_226b {
  strings:
    $key_226b = { 75 19 [2] 47 3b [2] 41 0e [2] 6f 0e [2] 50 12 }

  condition:
    any of them
}