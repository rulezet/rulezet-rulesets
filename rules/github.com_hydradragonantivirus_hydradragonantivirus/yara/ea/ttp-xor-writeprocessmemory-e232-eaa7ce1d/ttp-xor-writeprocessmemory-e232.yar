rule TTP_XOR_WriteProcessMemory_e232 {
  strings:
    $key_e232 = { b5 40 [2] 87 62 [2] 81 57 [2] af 57 [2] 90 4b }

  condition:
    any of them
}