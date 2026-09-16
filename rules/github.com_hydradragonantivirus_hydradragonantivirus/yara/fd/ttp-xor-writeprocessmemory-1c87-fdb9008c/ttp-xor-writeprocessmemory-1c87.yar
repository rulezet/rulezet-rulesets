rule TTP_XOR_WriteProcessMemory_1c87 {
  strings:
    $key_1c87 = { 4b f5 [2] 79 d7 [2] 7f e2 [2] 51 e2 [2] 6e fe }

  condition:
    any of them
}