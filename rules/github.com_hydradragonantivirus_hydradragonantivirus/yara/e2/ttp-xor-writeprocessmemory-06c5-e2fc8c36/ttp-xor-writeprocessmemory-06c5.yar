rule TTP_XOR_WriteProcessMemory_06c5 {
  strings:
    $key_06c5 = { 51 b7 [2] 63 95 [2] 65 a0 [2] 4b a0 [2] 74 bc }

  condition:
    any of them
}