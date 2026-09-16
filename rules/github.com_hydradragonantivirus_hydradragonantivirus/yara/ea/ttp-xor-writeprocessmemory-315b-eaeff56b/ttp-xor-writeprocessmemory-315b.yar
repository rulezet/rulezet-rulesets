rule TTP_XOR_WriteProcessMemory_315b {
  strings:
    $key_315b = { 66 29 [2] 54 0b [2] 52 3e [2] 7c 3e [2] 43 22 }

  condition:
    any of them
}