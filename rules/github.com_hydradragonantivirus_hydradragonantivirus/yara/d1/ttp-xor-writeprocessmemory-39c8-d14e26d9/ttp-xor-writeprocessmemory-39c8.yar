rule TTP_XOR_WriteProcessMemory_39c8 {
  strings:
    $key_39c8 = { 6e ba [2] 5c 98 [2] 5a ad [2] 74 ad [2] 4b b1 }

  condition:
    any of them
}