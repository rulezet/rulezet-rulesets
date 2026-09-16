rule TTP_XOR_WriteProcessMemory_3aa7 {
  strings:
    $key_3aa7 = { 6d d5 [2] 5f f7 [2] 59 c2 [2] 77 c2 [2] 48 de }

  condition:
    any of them
}