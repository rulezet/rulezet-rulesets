rule TTP_XOR_WriteProcessMemory_c029 {
  strings:
    $key_c029 = { 97 5b [2] a5 79 [2] a3 4c [2] 8d 4c [2] b2 50 }

  condition:
    any of them
}