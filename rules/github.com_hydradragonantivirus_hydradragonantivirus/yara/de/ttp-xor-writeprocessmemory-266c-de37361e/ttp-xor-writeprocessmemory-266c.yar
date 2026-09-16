rule TTP_XOR_WriteProcessMemory_266c {
  strings:
    $key_266c = { 71 1e [2] 43 3c [2] 45 09 [2] 6b 09 [2] 54 15 }

  condition:
    any of them
}