rule TTP_XOR_WriteProcessMemory_c641 {
  strings:
    $key_c641 = { 91 33 [2] a3 11 [2] a5 24 [2] 8b 24 [2] b4 38 }

  condition:
    any of them
}