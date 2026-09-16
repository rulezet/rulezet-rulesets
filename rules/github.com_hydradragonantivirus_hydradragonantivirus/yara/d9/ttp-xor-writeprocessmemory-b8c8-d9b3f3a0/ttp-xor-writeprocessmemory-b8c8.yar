rule TTP_XOR_WriteProcessMemory_b8c8 {
  strings:
    $key_b8c8 = { ef ba [2] dd 98 [2] db ad [2] f5 ad [2] ca b1 }

  condition:
    any of them
}