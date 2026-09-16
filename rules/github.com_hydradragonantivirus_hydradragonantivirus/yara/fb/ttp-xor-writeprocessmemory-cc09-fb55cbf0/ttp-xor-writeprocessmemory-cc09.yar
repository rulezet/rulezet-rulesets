rule TTP_XOR_WriteProcessMemory_cc09 {
  strings:
    $key_cc09 = { 9b 7b [2] a9 59 [2] af 6c [2] 81 6c [2] be 70 }

  condition:
    any of them
}