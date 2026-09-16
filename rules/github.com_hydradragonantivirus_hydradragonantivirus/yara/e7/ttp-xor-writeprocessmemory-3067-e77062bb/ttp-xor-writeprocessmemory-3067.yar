rule TTP_XOR_WriteProcessMemory_3067 {
  strings:
    $key_3067 = { 67 15 [2] 55 37 [2] 53 02 [2] 7d 02 [2] 42 1e }

  condition:
    any of them
}