rule TTP_XOR_WriteProcessMemory_e221 {
  strings:
    $key_e221 = { b5 53 [2] 87 71 [2] 81 44 [2] af 44 [2] 90 58 }

  condition:
    any of them
}