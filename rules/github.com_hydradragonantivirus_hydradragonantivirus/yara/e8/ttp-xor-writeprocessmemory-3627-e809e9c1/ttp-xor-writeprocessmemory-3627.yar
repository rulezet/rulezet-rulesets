rule TTP_XOR_WriteProcessMemory_3627 {
  strings:
    $key_3627 = { 61 55 [2] 53 77 [2] 55 42 [2] 7b 42 [2] 44 5e }

  condition:
    any of them
}