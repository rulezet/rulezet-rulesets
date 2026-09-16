rule TTP_XOR_WriteProcessMemory_6d77 {
  strings:
    $key_6d77 = { 3a 05 [2] 08 27 [2] 0e 12 [2] 20 12 [2] 1f 0e }

  condition:
    any of them
}