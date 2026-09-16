rule TTP_XOR_WriteProcessMemory_512b {
  strings:
    $key_512b = { 06 59 [2] 34 7b [2] 32 4e [2] 1c 4e [2] 23 52 }

  condition:
    any of them
}