rule TTP_XOR_WriteProcessMemory_e266 {
  strings:
    $key_e266 = { b5 14 [2] 87 36 [2] 81 03 [2] af 03 [2] 90 1f }

  condition:
    any of them
}