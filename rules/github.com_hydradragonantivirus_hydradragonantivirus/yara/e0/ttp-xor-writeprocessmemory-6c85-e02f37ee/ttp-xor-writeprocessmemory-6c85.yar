rule TTP_XOR_WriteProcessMemory_6c85 {
  strings:
    $key_6c85 = { 3b f7 [2] 09 d5 [2] 0f e0 [2] 21 e0 [2] 1e fc }

  condition:
    any of them
}