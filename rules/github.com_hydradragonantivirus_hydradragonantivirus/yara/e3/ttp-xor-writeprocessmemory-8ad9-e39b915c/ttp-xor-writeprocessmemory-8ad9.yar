rule TTP_XOR_WriteProcessMemory_8ad9 {
  strings:
    $key_8ad9 = { dd ab [2] ef 89 [2] e9 bc [2] c7 bc [2] f8 a0 }

  condition:
    any of them
}