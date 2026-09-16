rule TTP_XOR_WriteProcessMemory_dd07 {
  strings:
    $key_dd07 = { 8a 75 [2] b8 57 [2] be 62 [2] 90 62 [2] af 7e }

  condition:
    any of them
}