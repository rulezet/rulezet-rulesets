rule TTP_XOR_WriteProcessMemory_c209 {
  strings:
    $key_c209 = { 95 7b [2] a7 59 [2] a1 6c [2] 8f 6c [2] b0 70 }

  condition:
    any of them
}