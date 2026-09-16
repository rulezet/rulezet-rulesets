rule TTP_XOR_WriteProcessMemory_e927 {
  strings:
    $key_e927 = { be 55 [2] 8c 77 [2] 8a 42 [2] a4 42 [2] 9b 5e }

  condition:
    any of them
}