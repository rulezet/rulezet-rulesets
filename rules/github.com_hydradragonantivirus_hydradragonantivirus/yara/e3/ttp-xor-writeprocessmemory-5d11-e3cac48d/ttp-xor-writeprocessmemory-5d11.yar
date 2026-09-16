rule TTP_XOR_WriteProcessMemory_5d11 {
  strings:
    $key_5d11 = { 0a 63 [2] 38 41 [2] 3e 74 [2] 10 74 [2] 2f 68 }

  condition:
    any of them
}