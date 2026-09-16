rule TTP_XOR_WriteProcessMemory_36c8 {
  strings:
    $key_36c8 = { 61 ba [2] 53 98 [2] 55 ad [2] 7b ad [2] 44 b1 }

  condition:
    any of them
}