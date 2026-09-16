rule TTP_XOR_WriteProcessMemory_e327 {
  strings:
    $key_e327 = { b4 55 [2] 86 77 [2] 80 42 [2] ae 42 [2] 91 5e }

  condition:
    any of them
}