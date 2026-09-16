rule TTP_XOR_WriteProcessMemory_f8c8 {
  strings:
    $key_f8c8 = { af ba [2] 9d 98 [2] 9b ad [2] b5 ad [2] 8a b1 }

  condition:
    any of them
}