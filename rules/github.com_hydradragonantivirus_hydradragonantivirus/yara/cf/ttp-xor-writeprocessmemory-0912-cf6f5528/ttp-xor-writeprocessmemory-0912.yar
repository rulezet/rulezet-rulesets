rule TTP_XOR_WriteProcessMemory_0912 {
  strings:
    $key_0912 = { 5e 60 [2] 6c 42 [2] 6a 77 [2] 44 77 [2] 7b 6b }

  condition:
    any of them
}