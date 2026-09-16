rule TTP_XOR_WriteProcessMemory_06d9 {
  strings:
    $key_06d9 = { 51 ab [2] 63 89 [2] 65 bc [2] 4b bc [2] 74 a0 }

  condition:
    any of them
}