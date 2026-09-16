rule TTP_XOR_WriteProcessMemory_485b {
  strings:
    $key_485b = { 1f 29 [2] 2d 0b [2] 2b 3e [2] 05 3e [2] 3a 22 }

  condition:
    any of them
}