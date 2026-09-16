rule TTP_XOR_WriteProcessMemory_e187 {
  strings:
    $key_e187 = { b6 f5 [2] 84 d7 [2] 82 e2 [2] ac e2 [2] 93 fe }

  condition:
    any of them
}