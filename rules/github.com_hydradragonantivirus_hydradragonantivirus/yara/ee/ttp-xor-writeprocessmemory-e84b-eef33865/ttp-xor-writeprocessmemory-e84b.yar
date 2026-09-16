rule TTP_XOR_WriteProcessMemory_e84b {
  strings:
    $key_e84b = { bf 39 [2] 8d 1b [2] 8b 2e [2] a5 2e [2] 9a 32 }

  condition:
    any of them
}