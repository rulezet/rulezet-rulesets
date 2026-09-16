rule TTP_XOR_WriteProcessMemory_6531 {
  strings:
    $key_6531 = { 32 43 [2] 00 61 [2] 06 54 [2] 28 54 [2] 17 48 }

  condition:
    any of them
}