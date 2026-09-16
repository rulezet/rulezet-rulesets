rule TTP_XOR_WriteProcessMemory_3ad0 {
  strings:
    $key_3ad0 = { 6d a2 [2] 5f 80 [2] 59 b5 [2] 77 b5 [2] 48 a9 }

  condition:
    any of them
}