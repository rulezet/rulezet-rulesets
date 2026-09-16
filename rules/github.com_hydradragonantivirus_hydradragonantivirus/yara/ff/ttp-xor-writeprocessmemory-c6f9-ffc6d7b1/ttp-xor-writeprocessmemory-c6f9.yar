rule TTP_XOR_WriteProcessMemory_c6f9 {
  strings:
    $key_c6f9 = { 91 8b [2] a3 a9 [2] a5 9c [2] 8b 9c [2] b4 80 }

  condition:
    any of them
}