rule TTP_XOR_WriteProcessMemory_ddf7 {
  strings:
    $key_ddf7 = { 8a 85 [2] b8 a7 [2] be 92 [2] 90 92 [2] af 8e }

  condition:
    any of them
}