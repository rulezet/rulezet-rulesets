rule TTP_XOR_WriteProcessMemory_d369 {
  strings:
    $key_d369 = { 84 1b [2] b6 39 [2] b0 0c [2] 9e 0c [2] a1 10 }

  condition:
    any of them
}