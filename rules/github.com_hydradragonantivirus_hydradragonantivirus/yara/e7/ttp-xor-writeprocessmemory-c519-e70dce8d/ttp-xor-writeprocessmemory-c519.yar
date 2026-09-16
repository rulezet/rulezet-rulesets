rule TTP_XOR_WriteProcessMemory_c519 {
  strings:
    $key_c519 = { 92 6b [2] a0 49 [2] a6 7c [2] 88 7c [2] b7 60 }

  condition:
    any of them
}