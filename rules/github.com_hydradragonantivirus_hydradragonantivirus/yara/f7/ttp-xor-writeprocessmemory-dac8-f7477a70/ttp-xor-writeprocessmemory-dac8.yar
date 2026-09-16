rule TTP_XOR_WriteProcessMemory_dac8 {
  strings:
    $key_dac8 = { 8d ba [2] bf 98 [2] b9 ad [2] 97 ad [2] a8 b1 }

  condition:
    any of them
}