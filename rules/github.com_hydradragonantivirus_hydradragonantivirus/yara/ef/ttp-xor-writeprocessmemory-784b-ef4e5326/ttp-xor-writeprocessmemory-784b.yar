rule TTP_XOR_WriteProcessMemory_784b {
  strings:
    $key_784b = { 2f 39 [2] 1d 1b [2] 1b 2e [2] 35 2e [2] 0a 32 }

  condition:
    any of them
}