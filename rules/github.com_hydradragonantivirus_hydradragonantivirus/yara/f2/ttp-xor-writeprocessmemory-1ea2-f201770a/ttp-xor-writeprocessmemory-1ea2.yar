rule TTP_XOR_WriteProcessMemory_1ea2 {
  strings:
    $key_1ea2 = { 49 d0 [2] 7b f2 [2] 7d c7 [2] 53 c7 [2] 6c db }

  condition:
    any of them
}