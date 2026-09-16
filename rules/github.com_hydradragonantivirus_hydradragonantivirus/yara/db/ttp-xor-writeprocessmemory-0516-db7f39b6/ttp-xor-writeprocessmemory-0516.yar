rule TTP_XOR_WriteProcessMemory_0516 {
  strings:
    $key_0516 = { 52 64 [2] 60 46 [2] 66 73 [2] 48 73 [2] 77 6f }

  condition:
    any of them
}