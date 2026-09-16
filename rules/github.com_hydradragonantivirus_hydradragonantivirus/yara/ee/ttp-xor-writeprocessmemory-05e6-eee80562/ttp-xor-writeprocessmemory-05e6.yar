rule TTP_XOR_WriteProcessMemory_05e6 {
  strings:
    $key_05e6 = { 52 94 [2] 60 b6 [2] 66 83 [2] 48 83 [2] 77 9f }

  condition:
    any of them
}