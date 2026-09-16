rule TTP_XOR_WriteProcessMemory_32c7 {
  strings:
    $key_32c7 = { 65 b5 [2] 57 97 [2] 51 a2 [2] 7f a2 [2] 40 be }

  condition:
    any of them
}