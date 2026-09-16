rule TTP_XOR_WriteProcessMemory_fcf0 {
  strings:
    $key_fcf0 = { ab 82 [2] 99 a0 [2] 9f 95 [2] b1 95 [2] 8e 89 }

  condition:
    any of them
}