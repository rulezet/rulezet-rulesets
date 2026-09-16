rule TTP_XOR_WriteProcessMemory_ddf2 {
  strings:
    $key_ddf2 = { 8a 80 [2] b8 a2 [2] be 97 [2] 90 97 [2] af 8b }

  condition:
    any of them
}