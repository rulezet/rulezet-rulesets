rule TTP_XOR_WriteProcessMemory_dde0 {
  strings:
    $key_dde0 = { 8a 92 [2] b8 b0 [2] be 85 [2] 90 85 [2] af 99 }

  condition:
    any of them
}