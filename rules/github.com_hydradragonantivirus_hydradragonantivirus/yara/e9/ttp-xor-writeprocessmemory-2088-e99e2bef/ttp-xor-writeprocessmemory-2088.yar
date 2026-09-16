rule TTP_XOR_WriteProcessMemory_2088 {
  strings:
    $key_2088 = { 77 fa [2] 45 d8 [2] 43 ed [2] 6d ed [2] 52 f1 }

  condition:
    any of them
}