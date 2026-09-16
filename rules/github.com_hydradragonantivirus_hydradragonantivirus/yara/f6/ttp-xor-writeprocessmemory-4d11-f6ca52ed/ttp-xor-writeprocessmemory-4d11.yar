rule TTP_XOR_WriteProcessMemory_4d11 {
  strings:
    $key_4d11 = { 1a 63 [2] 28 41 [2] 2e 74 [2] 00 74 [2] 3f 68 }

  condition:
    any of them
}