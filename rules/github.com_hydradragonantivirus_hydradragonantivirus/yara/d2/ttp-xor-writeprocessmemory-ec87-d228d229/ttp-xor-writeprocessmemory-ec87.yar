rule TTP_XOR_WriteProcessMemory_ec87 {
  strings:
    $key_ec87 = { bb f5 [2] 89 d7 [2] 8f e2 [2] a1 e2 [2] 9e fe }

  condition:
    any of them
}