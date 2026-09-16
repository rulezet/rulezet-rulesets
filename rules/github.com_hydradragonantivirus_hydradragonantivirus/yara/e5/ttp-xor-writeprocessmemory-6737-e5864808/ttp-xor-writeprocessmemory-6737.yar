rule TTP_XOR_WriteProcessMemory_6737 {
  strings:
    $key_6737 = { 30 45 [2] 02 67 [2] 04 52 [2] 2a 52 [2] 15 4e }

  condition:
    any of them
}