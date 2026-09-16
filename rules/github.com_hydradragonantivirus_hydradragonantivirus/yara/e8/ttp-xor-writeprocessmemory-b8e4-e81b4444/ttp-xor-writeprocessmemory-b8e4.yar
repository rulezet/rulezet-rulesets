rule TTP_XOR_WriteProcessMemory_b8e4 {
  strings:
    $key_b8e4 = { ef 96 [2] dd b4 [2] db 81 [2] f5 81 [2] ca 9d }

  condition:
    any of them
}