rule TTP_XOR_WriteProcessMemory_1e85 {
  strings:
    $key_1e85 = { 49 f7 [2] 7b d5 [2] 7d e0 [2] 53 e0 [2] 6c fc }

  condition:
    any of them
}