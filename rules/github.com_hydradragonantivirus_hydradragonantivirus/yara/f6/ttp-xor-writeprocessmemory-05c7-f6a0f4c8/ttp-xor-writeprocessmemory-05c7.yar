rule TTP_XOR_WriteProcessMemory_05c7 {
  strings:
    $key_05c7 = { 52 b5 [2] 60 97 [2] 66 a2 [2] 48 a2 [2] 77 be }

  condition:
    any of them
}