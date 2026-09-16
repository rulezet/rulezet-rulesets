rule TTP_XOR_WriteProcessMemory_1ec8 {
  strings:
    $key_1ec8 = { 49 ba [2] 7b 98 [2] 7d ad [2] 53 ad [2] 6c b1 }

  condition:
    any of them
}