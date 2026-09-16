rule TTP_XOR_WriteProcessMemory_b80e {
  strings:
    $key_b80e = { ef 7c [2] dd 5e [2] db 6b [2] f5 6b [2] ca 77 }

  condition:
    any of them
}