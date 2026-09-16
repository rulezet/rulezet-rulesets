rule TTP_XOR_WriteProcessMemory_ed57 {
  strings:
    $key_ed57 = { ba 25 [2] 88 07 [2] 8e 32 [2] a0 32 [2] 9f 2e }

  condition:
    any of them
}