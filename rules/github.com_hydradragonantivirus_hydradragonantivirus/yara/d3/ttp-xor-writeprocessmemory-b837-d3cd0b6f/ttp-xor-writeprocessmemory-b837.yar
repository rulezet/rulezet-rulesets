rule TTP_XOR_WriteProcessMemory_b837 {
  strings:
    $key_b837 = { ef 45 [2] dd 67 [2] db 52 [2] f5 52 [2] ca 4e }

  condition:
    any of them
}