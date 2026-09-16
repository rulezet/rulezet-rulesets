rule TTP_XOR_WriteProcessMemory_2aa3 {
  strings:
    $key_2aa3 = { 7d d1 [2] 4f f3 [2] 49 c6 [2] 67 c6 [2] 58 da }

  condition:
    any of them
}