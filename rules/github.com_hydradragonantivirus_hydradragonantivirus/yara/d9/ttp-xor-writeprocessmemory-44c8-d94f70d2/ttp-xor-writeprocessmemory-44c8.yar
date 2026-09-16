rule TTP_XOR_WriteProcessMemory_44c8 {
  strings:
    $key_44c8 = { 13 ba [2] 21 98 [2] 27 ad [2] 09 ad [2] 36 b1 }

  condition:
    any of them
}