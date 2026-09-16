rule TTP_XOR_WriteProcessMemory_3ac1 {
  strings:
    $key_3ac1 = { 6d b3 [2] 5f 91 [2] 59 a4 [2] 77 a4 [2] 48 b8 }

  condition:
    any of them
}