rule TTP_XOR_WriteProcessMemory_e2f2 {
  strings:
    $key_e2f2 = { b5 80 [2] 87 a2 [2] 81 97 [2] af 97 [2] 90 8b }

  condition:
    any of them
}