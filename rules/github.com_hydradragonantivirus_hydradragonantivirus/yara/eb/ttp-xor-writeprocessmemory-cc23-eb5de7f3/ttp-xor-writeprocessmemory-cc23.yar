rule TTP_XOR_WriteProcessMemory_cc23 {
  strings:
    $key_cc23 = { 9b 51 [2] a9 73 [2] af 46 [2] 81 46 [2] be 5a }

  condition:
    any of them
}