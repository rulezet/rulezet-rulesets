rule TTP_XOR_WriteProcessMemory_e243 {
  strings:
    $key_e243 = { b5 31 [2] 87 13 [2] 81 26 [2] af 26 [2] 90 3a }

  condition:
    any of them
}