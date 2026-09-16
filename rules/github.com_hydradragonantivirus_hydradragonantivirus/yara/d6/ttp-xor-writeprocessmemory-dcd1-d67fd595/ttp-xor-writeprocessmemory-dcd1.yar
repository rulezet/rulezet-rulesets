rule TTP_XOR_WriteProcessMemory_dcd1 {
  strings:
    $key_dcd1 = { 8b a3 [2] b9 81 [2] bf b4 [2] 91 b4 [2] ae a8 }

  condition:
    any of them
}