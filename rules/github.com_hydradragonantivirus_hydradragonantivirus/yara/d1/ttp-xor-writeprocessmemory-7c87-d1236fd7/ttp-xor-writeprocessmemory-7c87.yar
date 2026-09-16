rule TTP_XOR_WriteProcessMemory_7c87 {
  strings:
    $key_7c87 = { 2b f5 [2] 19 d7 [2] 1f e2 [2] 31 e2 [2] 0e fe }

  condition:
    any of them
}