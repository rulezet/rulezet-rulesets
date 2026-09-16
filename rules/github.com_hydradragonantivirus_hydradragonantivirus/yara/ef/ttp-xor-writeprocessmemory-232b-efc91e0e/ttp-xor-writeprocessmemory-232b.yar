rule TTP_XOR_WriteProcessMemory_232b {
  strings:
    $key_232b = { 74 59 [2] 46 7b [2] 40 4e [2] 6e 4e [2] 51 52 }

  condition:
    any of them
}