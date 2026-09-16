rule TTP_XOR_WriteProcessMemory_e137 {
  strings:
    $key_e137 = { b6 45 [2] 84 67 [2] 82 52 [2] ac 52 [2] 93 4e }

  condition:
    any of them
}