rule TTP_XOR_WriteProcessMemory_c617 {
  strings:
    $key_c617 = { 91 65 [2] a3 47 [2] a5 72 [2] 8b 72 [2] b4 6e }

  condition:
    any of them
}