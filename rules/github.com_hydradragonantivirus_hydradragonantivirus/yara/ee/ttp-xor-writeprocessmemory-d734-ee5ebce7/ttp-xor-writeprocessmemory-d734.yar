rule TTP_XOR_WriteProcessMemory_d734 {
  strings:
    $key_d734 = { 80 46 [2] b2 64 [2] b4 51 [2] 9a 51 [2] a5 4d }

  condition:
    any of them
}