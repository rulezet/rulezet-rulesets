rule TTP_XOR_WriteProcessMemory_7c85 {
  strings:
    $key_7c85 = { 2b f7 [2] 19 d5 [2] 1f e0 [2] 31 e0 [2] 0e fc }

  condition:
    any of them
}