rule TTP_XOR_WriteProcessMemory_3c85 {
  strings:
    $key_3c85 = { 6b f7 [2] 59 d5 [2] 5f e0 [2] 71 e0 [2] 4e fc }

  condition:
    any of them
}