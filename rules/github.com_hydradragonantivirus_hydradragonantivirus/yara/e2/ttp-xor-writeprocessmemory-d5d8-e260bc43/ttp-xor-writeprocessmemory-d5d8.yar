rule TTP_XOR_WriteProcessMemory_d5d8 {
  strings:
    $key_d5d8 = { 82 aa [2] b0 88 [2] b6 bd [2] 98 bd [2] a7 a1 }

  condition:
    any of them
}