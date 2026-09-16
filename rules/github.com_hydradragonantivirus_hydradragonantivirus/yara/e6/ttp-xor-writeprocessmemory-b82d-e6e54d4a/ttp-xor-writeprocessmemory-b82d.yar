rule TTP_XOR_WriteProcessMemory_b82d {
  strings:
    $key_b82d = { ef 5f [2] dd 7d [2] db 48 [2] f5 48 [2] ca 54 }

  condition:
    any of them
}