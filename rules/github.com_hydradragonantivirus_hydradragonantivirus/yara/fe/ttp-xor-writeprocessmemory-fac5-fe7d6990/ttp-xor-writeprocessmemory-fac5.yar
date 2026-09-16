rule TTP_XOR_WriteProcessMemory_fac5 {
  strings:
    $key_fac5 = { ad b7 [2] 9f 95 [2] 99 a0 [2] b7 a0 [2] 88 bc }

  condition:
    any of them
}