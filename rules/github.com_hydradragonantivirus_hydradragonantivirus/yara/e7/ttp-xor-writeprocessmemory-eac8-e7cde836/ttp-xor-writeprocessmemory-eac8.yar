rule TTP_XOR_WriteProcessMemory_eac8 {
  strings:
    $key_eac8 = { bd ba [2] 8f 98 [2] 89 ad [2] a7 ad [2] 98 b1 }

  condition:
    any of them
}