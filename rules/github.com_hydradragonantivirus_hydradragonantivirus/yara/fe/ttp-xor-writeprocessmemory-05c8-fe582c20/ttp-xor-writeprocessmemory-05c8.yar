rule TTP_XOR_WriteProcessMemory_05c8 {
  strings:
    $key_05c8 = { 52 ba [2] 60 98 [2] 66 ad [2] 48 ad [2] 77 b1 }

  condition:
    any of them
}