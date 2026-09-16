rule TTP_XOR_WriteProcessMemory_0d85 {
  strings:
    $key_0d85 = { 5a f7 [2] 68 d5 [2] 6e e0 [2] 40 e0 [2] 7f fc }

  condition:
    any of them
}