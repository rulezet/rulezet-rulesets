rule TTP_XOR_WriteProcessMemory_1d11 {
  strings:
    $key_1d11 = { 4a 63 [2] 78 41 [2] 7e 74 [2] 50 74 [2] 6f 68 }

  condition:
    any of them
}