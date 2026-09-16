rule TTP_XOR_WriteProcessMemory_4c84 {
  strings:
    $key_4c84 = { 1b f6 [2] 29 d4 [2] 2f e1 [2] 01 e1 [2] 3e fd }

  condition:
    any of them
}