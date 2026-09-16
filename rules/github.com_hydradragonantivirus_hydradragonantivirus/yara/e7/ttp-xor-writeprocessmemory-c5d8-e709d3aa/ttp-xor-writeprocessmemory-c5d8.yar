rule TTP_XOR_WriteProcessMemory_c5d8 {
  strings:
    $key_c5d8 = { 92 aa [2] a0 88 [2] a6 bd [2] 88 bd [2] b7 a1 }

  condition:
    any of them
}