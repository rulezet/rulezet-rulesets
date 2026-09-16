rule TTP_XOR_WriteProcessMemory_78c7 {
  strings:
    $key_78c7 = { 2f b5 [2] 1d 97 [2] 1b a2 [2] 35 a2 [2] 0a be }

  condition:
    any of them
}