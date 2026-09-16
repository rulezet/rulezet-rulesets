rule TTP_XOR_WriteProcessMemory_24a3 {
  strings:
    $key_24a3 = { 73 d1 [2] 41 f3 [2] 47 c6 [2] 69 c6 [2] 56 da }

  condition:
    any of them
}