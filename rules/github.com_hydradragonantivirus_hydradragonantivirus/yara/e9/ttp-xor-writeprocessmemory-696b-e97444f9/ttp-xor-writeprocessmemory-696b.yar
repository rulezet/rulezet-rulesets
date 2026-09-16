rule TTP_XOR_WriteProcessMemory_696b {
  strings:
    $key_696b = { 3e 19 [2] 0c 3b [2] 0a 0e [2] 24 0e [2] 1b 12 }

  condition:
    any of them
}