rule TTP_XOR_WriteProcessMemory_ddc3 {
  strings:
    $key_ddc3 = { 8a b1 [2] b8 93 [2] be a6 [2] 90 a6 [2] af ba }

  condition:
    any of them
}