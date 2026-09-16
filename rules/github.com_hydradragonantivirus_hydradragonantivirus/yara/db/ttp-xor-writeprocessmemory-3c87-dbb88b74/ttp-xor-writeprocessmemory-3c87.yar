rule TTP_XOR_WriteProcessMemory_3c87 {
  strings:
    $key_3c87 = { 6b f5 [2] 59 d7 [2] 5f e2 [2] 71 e2 [2] 4e fe }

  condition:
    any of them
}