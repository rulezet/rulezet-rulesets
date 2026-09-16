rule TTP_XOR_WriteProcessMemory_12c7 {
  strings:
    $key_12c7 = { 45 b5 [2] 77 97 [2] 71 a2 [2] 5f a2 [2] 60 be }

  condition:
    any of them
}