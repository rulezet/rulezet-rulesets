rule TTP_XOR_WriteProcessMemory_d509 {
  strings:
    $key_d509 = { 82 7b [2] b0 59 [2] b6 6c [2] 98 6c [2] a7 70 }

  condition:
    any of them
}