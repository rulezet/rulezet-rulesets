rule TTP_XOR_WriteProcessMemory_b84a {
  strings:
    $key_b84a = { ef 38 [2] dd 1a [2] db 2f [2] f5 2f [2] ca 33 }

  condition:
    any of them
}