rule TTP_XOR_WriteProcessMemory_fac8 {
  strings:
    $key_fac8 = { ad ba [2] 9f 98 [2] 99 ad [2] b7 ad [2] 88 b1 }

  condition:
    any of them
}