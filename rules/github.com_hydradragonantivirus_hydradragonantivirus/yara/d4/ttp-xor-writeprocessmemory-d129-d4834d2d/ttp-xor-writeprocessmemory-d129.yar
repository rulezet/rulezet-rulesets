rule TTP_XOR_WriteProcessMemory_d129 {
  strings:
    $key_d129 = { 86 5b [2] b4 79 [2] b2 4c [2] 9c 4c [2] a3 50 }

  condition:
    any of them
}