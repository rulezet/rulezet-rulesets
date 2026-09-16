rule TTP_XOR_WriteProcessMemory_4c85 {
  strings:
    $key_4c85 = { 1b f7 [2] 29 d5 [2] 2f e0 [2] 01 e0 [2] 3e fc }

  condition:
    any of them
}