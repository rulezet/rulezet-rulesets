rule TTP_XOR_WriteProcessMemory_0c85 {
  strings:
    $key_0c85 = { 5b f7 [2] 69 d5 [2] 6f e0 [2] 41 e0 [2] 7e fc }

  condition:
    any of them
}