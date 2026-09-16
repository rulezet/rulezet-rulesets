rule TTP_XOR_WriteProcessMemory_0504 {
  strings:
    $key_0504 = { 52 76 [2] 60 54 [2] 66 61 [2] 48 61 [2] 77 7d }

  condition:
    any of them
}