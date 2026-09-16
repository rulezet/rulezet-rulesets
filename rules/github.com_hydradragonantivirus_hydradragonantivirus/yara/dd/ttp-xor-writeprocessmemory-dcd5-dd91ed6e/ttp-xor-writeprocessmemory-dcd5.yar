rule TTP_XOR_WriteProcessMemory_dcd5 {
  strings:
    $key_dcd5 = { 8b a7 [2] b9 85 [2] bf b0 [2] 91 b0 [2] ae ac }

  condition:
    any of them
}