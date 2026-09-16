rule TTP_XOR_WriteProcessMemory_c629 {
  strings:
    $key_c629 = { 91 5b [2] a3 79 [2] a5 4c [2] 8b 4c [2] b4 50 }

  condition:
    any of them
}