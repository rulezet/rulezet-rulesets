rule TTP_XOR_WriteProcessMemory_2e85 {
  strings:
    $key_2e85 = { 79 f7 [2] 4b d5 [2] 4d e0 [2] 63 e0 [2] 5c fc }

  condition:
    any of them
}