rule TTP_XOR_WriteProcessMemory_e145 {
  strings:
    $key_e145 = { b6 37 [2] 84 15 [2] 82 20 [2] ac 20 [2] 93 3c }

  condition:
    any of them
}