rule TTP_XOR_WriteProcessMemory_3537 {
  strings:
    $key_3537 = { 62 45 [2] 50 67 [2] 56 52 [2] 78 52 [2] 47 4e }

  condition:
    any of them
}