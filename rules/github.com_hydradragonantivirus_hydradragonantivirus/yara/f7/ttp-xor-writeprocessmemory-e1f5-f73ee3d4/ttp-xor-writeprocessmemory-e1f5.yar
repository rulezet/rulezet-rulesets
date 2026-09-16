rule TTP_XOR_WriteProcessMemory_e1f5 {
  strings:
    $key_e1f5 = { b6 87 [2] 84 a5 [2] 82 90 [2] ac 90 [2] 93 8c }

  condition:
    any of them
}