rule TTP_XOR_WriteProcessMemory_38a6 {
  strings:
    $key_38a6 = { 6f d4 [2] 5d f6 [2] 5b c3 [2] 75 c3 [2] 4a df }

  condition:
    any of them
}