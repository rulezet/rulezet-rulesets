rule TTP_XOR_WriteProcessMemory_b811 {
  strings:
    $key_b811 = { ef 63 [2] dd 41 [2] db 74 [2] f5 74 [2] ca 68 }

  condition:
    any of them
}