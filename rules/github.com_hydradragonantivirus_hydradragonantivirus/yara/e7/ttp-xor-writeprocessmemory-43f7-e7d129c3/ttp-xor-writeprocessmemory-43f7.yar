rule TTP_XOR_WriteProcessMemory_43f7 {
  strings:
    $key_43f7 = { 14 85 [2] 26 a7 [2] 20 92 [2] 0e 92 [2] 31 8e }

  condition:
    any of them
}