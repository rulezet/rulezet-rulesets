rule TTP_XOR_WriteProcessMemory_d587 {
  strings:
    $key_d587 = { 82 f5 [2] b0 d7 [2] b6 e2 [2] 98 e2 [2] a7 fe }

  condition:
    any of them
}