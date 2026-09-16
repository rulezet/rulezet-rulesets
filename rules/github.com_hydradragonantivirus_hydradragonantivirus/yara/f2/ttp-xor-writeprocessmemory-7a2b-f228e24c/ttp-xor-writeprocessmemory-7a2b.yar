rule TTP_XOR_WriteProcessMemory_7a2b {
  strings:
    $key_7a2b = { 2d 59 [2] 1f 7b [2] 19 4e [2] 37 4e [2] 08 52 }

  condition:
    any of them
}