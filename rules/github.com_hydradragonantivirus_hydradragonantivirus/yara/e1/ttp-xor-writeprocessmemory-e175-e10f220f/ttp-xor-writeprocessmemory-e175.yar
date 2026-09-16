rule TTP_XOR_WriteProcessMemory_e175 {
  strings:
    $key_e175 = { b6 07 [2] 84 25 [2] 82 10 [2] ac 10 [2] 93 0c }

  condition:
    any of them
}