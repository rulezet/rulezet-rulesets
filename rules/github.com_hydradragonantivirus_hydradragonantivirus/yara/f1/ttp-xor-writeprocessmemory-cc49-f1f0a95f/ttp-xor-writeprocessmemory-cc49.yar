rule TTP_XOR_WriteProcessMemory_cc49 {
  strings:
    $key_cc49 = { 9b 3b [2] a9 19 [2] af 2c [2] 81 2c [2] be 30 }

  condition:
    any of them
}