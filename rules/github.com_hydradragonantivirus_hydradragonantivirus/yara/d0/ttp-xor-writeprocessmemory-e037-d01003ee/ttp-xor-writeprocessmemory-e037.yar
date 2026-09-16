rule TTP_XOR_WriteProcessMemory_e037 {
  strings:
    $key_e037 = { b7 45 [2] 85 67 [2] 83 52 [2] ad 52 [2] 92 4e }

  condition:
    any of them
}