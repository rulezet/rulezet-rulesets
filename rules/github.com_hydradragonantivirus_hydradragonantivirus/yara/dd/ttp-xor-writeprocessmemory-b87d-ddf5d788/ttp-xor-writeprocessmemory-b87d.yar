rule TTP_XOR_WriteProcessMemory_b87d {
  strings:
    $key_b87d = { ef 0f [2] dd 2d [2] db 18 [2] f5 18 [2] ca 04 }

  condition:
    any of them
}