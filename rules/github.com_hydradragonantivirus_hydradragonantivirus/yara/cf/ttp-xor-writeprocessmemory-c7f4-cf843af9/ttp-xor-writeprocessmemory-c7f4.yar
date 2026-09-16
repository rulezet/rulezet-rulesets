rule TTP_XOR_WriteProcessMemory_c7f4 {
  strings:
    $key_c7f4 = { 90 86 [2] a2 a4 [2] a4 91 [2] 8a 91 [2] b5 8d }

  condition:
    any of them
}