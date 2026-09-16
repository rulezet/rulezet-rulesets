rule TTP_XOR_WriteProcessMemory_0aa6 {
  strings:
    $key_0aa6 = { 5d d4 [2] 6f f6 [2] 69 c3 [2] 47 c3 [2] 78 df }

  condition:
    any of them
}