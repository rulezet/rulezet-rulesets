rule TTP_XOR_WriteProcessMemory_262d {
  strings:
    $key_262d = { 71 5f [2] 43 7d [2] 45 48 [2] 6b 48 [2] 54 54 }

  condition:
    any of them
}