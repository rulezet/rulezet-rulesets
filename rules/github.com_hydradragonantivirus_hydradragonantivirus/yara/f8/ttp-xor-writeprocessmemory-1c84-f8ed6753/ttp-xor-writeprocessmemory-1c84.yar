rule TTP_XOR_WriteProcessMemory_1c84 {
  strings:
    $key_1c84 = { 4b f6 [2] 79 d4 [2] 7f e1 [2] 51 e1 [2] 6e fd }

  condition:
    any of them
}