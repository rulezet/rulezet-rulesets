rule TTP_XOR_WriteProcessMemory_e216 {
  strings:
    $key_e216 = { b5 64 [2] 87 46 [2] 81 73 [2] af 73 [2] 90 6f }

  condition:
    any of them
}