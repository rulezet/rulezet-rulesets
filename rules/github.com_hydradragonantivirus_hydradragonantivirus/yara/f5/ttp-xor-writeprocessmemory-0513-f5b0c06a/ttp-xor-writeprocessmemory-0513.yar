rule TTP_XOR_WriteProcessMemory_0513 {
  strings:
    $key_0513 = { 52 61 [2] 60 43 [2] 66 76 [2] 48 76 [2] 77 6a }

  condition:
    any of them
}