rule TTP_XOR_WriteProcessMemory_dde7 {
  strings:
    $key_dde7 = { 8a 95 [2] b8 b7 [2] be 82 [2] 90 82 [2] af 9e }

  condition:
    any of them
}