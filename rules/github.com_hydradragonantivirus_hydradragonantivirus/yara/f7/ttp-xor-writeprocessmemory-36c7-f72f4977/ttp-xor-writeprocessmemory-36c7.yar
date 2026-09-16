rule TTP_XOR_WriteProcessMemory_36c7 {
  strings:
    $key_36c7 = { 61 b5 [2] 53 97 [2] 55 a2 [2] 7b a2 [2] 44 be }

  condition:
    any of them
}