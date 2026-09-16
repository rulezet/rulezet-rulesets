rule TTP_XOR_WriteProcessMemory_0963 {
  strings:
    $key_0963 = { 5e 11 [2] 6c 33 [2] 6a 06 [2] 44 06 [2] 7b 1a }

  condition:
    any of them
}