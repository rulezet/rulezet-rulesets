rule TTP_XOR_WriteProcessMemory_cc19 {
  strings:
    $key_cc19 = { 9b 6b [2] a9 49 [2] af 7c [2] 81 7c [2] be 60 }

  condition:
    any of them
}