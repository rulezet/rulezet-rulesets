rule TTP_XOR_WriteProcessMemory_e165 {
  strings:
    $key_e165 = { b6 17 [2] 84 35 [2] 82 00 [2] ac 00 [2] 93 1c }

  condition:
    any of them
}