rule TTP_XOR_WriteProcessMemory_3ad9 {
  strings:
    $key_3ad9 = { 6d ab [2] 5f 89 [2] 59 bc [2] 77 bc [2] 48 a0 }

  condition:
    any of them
}