rule TTP_XOR_WriteProcessMemory_d539 {
  strings:
    $key_d539 = { 82 4b [2] b0 69 [2] b6 5c [2] 98 5c [2] a7 40 }

  condition:
    any of them
}