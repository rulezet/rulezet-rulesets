rule TTP_XOR_WriteProcessMemory_3ad1 {
  strings:
    $key_3ad1 = { 6d a3 [2] 5f 81 [2] 59 b4 [2] 77 b4 [2] 48 a8 }

  condition:
    any of them
}