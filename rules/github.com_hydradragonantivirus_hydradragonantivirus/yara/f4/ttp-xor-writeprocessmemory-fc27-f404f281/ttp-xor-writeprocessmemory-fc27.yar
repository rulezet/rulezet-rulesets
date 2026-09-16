rule TTP_XOR_WriteProcessMemory_fc27 {
  strings:
    $key_fc27 = { ab 55 [2] 99 77 [2] 9f 42 [2] b1 42 [2] 8e 5e }

  condition:
    any of them
}