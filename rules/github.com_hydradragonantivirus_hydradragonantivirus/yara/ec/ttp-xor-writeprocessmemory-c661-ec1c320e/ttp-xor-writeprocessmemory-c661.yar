rule TTP_XOR_WriteProcessMemory_c661 {
  strings:
    $key_c661 = { 91 13 [2] a3 31 [2] a5 04 [2] 8b 04 [2] b4 18 }

  condition:
    any of them
}