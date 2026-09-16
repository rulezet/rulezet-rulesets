rule TTP_XOR_WriteProcessMemory_b864 {
  strings:
    $key_b864 = { ef 16 [2] dd 34 [2] db 01 [2] f5 01 [2] ca 1d }

  condition:
    any of them
}