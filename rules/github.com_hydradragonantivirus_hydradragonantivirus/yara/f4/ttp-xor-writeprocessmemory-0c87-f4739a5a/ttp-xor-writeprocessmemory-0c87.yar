rule TTP_XOR_WriteProcessMemory_0c87 {
  strings:
    $key_0c87 = { 5b f5 [2] 69 d7 [2] 6f e2 [2] 41 e2 [2] 7e fe }

  condition:
    any of them
}