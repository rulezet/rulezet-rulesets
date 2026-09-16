rule TTP_XOR_WriteProcessMemory_3cb6 {
  strings:
    $key_3cb6 = { 6b c4 [2] 59 e6 [2] 5f d3 [2] 71 d3 [2] 4e cf }

  condition:
    any of them
}