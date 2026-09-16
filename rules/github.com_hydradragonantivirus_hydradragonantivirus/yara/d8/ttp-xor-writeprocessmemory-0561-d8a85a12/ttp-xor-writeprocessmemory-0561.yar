rule TTP_XOR_WriteProcessMemory_0561 {
  strings:
    $key_0561 = { 52 13 [2] 60 31 [2] 66 04 [2] 48 04 [2] 77 18 }

  condition:
    any of them
}