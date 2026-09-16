rule TTP_XOR_WriteProcessMemory_c259 {
  strings:
    $key_c259 = { 95 2b [2] a7 09 [2] a1 3c [2] 8f 3c [2] b0 20 }

  condition:
    any of them
}