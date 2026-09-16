rule TTP_XOR_WriteProcessMemory_31c8 {
  strings:
    $key_31c8 = { 66 ba [2] 54 98 [2] 52 ad [2] 7c ad [2] 43 b1 }

  condition:
    any of them
}