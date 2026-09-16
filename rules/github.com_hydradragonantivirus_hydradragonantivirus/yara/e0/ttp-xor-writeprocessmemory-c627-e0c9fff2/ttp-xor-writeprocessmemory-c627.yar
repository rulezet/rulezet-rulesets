rule TTP_XOR_WriteProcessMemory_c627 {
  strings:
    $key_c627 = { 91 55 [2] a3 77 [2] a5 42 [2] 8b 42 [2] b4 5e }

  condition:
    any of them
}