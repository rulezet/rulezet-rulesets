rule TTP_XOR_WriteProcessMemory_0a27 {
  strings:
    $key_0a27 = { 5d 55 [2] 6f 77 [2] 69 42 [2] 47 42 [2] 78 5e }

  condition:
    any of them
}