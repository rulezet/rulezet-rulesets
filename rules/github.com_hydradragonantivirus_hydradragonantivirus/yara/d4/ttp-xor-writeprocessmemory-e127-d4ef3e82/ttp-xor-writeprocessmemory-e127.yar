rule TTP_XOR_WriteProcessMemory_e127 {
  strings:
    $key_e127 = { b6 55 [2] 84 77 [2] 82 42 [2] ac 42 [2] 93 5e }

  condition:
    any of them
}