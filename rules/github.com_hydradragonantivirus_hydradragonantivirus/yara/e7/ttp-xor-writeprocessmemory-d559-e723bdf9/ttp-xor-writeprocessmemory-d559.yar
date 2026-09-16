rule TTP_XOR_WriteProcessMemory_d559 {
  strings:
    $key_d559 = { 82 2b [2] b0 09 [2] b6 3c [2] 98 3c [2] a7 20 }

  condition:
    any of them
}