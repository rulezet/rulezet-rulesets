rule TTP_XOR_WriteProcessMemory_c437 {
  strings:
    $key_c437 = { 93 45 [2] a1 67 [2] a7 52 [2] 89 52 [2] b6 4e }

  condition:
    any of them
}