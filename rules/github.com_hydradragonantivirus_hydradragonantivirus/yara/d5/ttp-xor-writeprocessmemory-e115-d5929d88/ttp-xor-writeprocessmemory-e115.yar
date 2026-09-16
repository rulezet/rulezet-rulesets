rule TTP_XOR_WriteProcessMemory_e115 {
  strings:
    $key_e115 = { b6 67 [2] 84 45 [2] 82 70 [2] ac 70 [2] 93 6c }

  condition:
    any of them
}