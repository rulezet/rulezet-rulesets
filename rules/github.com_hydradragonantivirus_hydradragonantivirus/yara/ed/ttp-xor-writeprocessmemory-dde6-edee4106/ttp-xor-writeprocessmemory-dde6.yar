rule TTP_XOR_WriteProcessMemory_dde6 {
  strings:
    $key_dde6 = { 8a 94 [2] b8 b6 [2] be 83 [2] 90 83 [2] af 9f }

  condition:
    any of them
}