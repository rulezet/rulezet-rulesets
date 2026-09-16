rule TTP_XOR_WriteProcessMemory_e197 {
  strings:
    $key_e197 = { b6 e5 [2] 84 c7 [2] 82 f2 [2] ac f2 [2] 93 ee }

  condition:
    any of them
}