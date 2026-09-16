rule TTP_XOR_WriteProcessMemory_c129 {
  strings:
    $key_c129 = { 96 5b [2] a4 79 [2] a2 4c [2] 8c 4c [2] b3 50 }

  condition:
    any of them
}