rule TTP_XOR_WriteProcessMemory_fcf1 {
  strings:
    $key_fcf1 = { ab 83 [2] 99 a1 [2] 9f 94 [2] b1 94 [2] 8e 88 }

  condition:
    any of them
}