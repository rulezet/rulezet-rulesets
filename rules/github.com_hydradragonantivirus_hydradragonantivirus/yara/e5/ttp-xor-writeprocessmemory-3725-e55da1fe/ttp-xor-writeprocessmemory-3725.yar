rule TTP_XOR_WriteProcessMemory_3725 {
  strings:
    $key_3725 = { 60 57 [2] 52 75 [2] 54 40 [2] 7a 40 [2] 45 5c }

  condition:
    any of them
}