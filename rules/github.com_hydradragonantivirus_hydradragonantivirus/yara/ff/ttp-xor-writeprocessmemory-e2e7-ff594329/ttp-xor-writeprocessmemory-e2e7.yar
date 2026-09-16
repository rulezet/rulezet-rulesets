rule TTP_XOR_WriteProcessMemory_e2e7 {
  strings:
    $key_e2e7 = { b5 95 [2] 87 b7 [2] 81 82 [2] af 82 [2] 90 9e }

  condition:
    any of them
}