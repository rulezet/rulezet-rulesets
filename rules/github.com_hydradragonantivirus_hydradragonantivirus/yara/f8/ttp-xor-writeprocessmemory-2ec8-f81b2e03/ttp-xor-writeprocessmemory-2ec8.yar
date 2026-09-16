rule TTP_XOR_WriteProcessMemory_2ec8 {
  strings:
    $key_2ec8 = { 79 ba [2] 4b 98 [2] 4d ad [2] 63 ad [2] 5c b1 }

  condition:
    any of them
}