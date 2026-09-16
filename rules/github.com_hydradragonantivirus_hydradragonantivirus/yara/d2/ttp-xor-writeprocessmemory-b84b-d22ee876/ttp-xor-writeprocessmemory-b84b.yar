rule TTP_XOR_WriteProcessMemory_b84b {
  strings:
    $key_b84b = { ef 39 [2] dd 1b [2] db 2e [2] f5 2e [2] ca 32 }

  condition:
    any of them
}