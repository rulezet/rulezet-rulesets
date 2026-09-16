rule TTP_XOR_WriteProcessMemory_cc88 {
  strings:
    $key_cc88 = { 9b fa [2] a9 d8 [2] af ed [2] 81 ed [2] be f1 }

  condition:
    any of them
}