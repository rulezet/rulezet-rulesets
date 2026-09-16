rule TTP_XOR_WriteProcessMemory_b82f {
  strings:
    $key_b82f = { ef 5d [2] dd 7f [2] db 4a [2] f5 4a [2] ca 56 }

  condition:
    any of them
}