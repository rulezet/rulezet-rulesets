rule TTP_XOR_WriteProcessMemory_260b {
  strings:
    $key_260b = { 71 79 [2] 43 5b [2] 45 6e [2] 6b 6e [2] 54 72 }

  condition:
    any of them
}