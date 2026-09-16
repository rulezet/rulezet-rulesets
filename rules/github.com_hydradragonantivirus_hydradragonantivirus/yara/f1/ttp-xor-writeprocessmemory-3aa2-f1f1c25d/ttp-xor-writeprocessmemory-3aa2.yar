rule TTP_XOR_WriteProcessMemory_3aa2 {
  strings:
    $key_3aa2 = { 6d d0 [2] 5f f2 [2] 59 c7 [2] 77 c7 [2] 48 db }

  condition:
    any of them
}