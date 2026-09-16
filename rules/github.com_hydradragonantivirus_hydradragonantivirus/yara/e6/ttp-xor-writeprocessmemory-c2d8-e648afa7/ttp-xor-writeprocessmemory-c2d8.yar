rule TTP_XOR_WriteProcessMemory_c2d8 {
  strings:
    $key_c2d8 = { 95 aa [2] a7 88 [2] a1 bd [2] 8f bd [2] b0 a1 }

  condition:
    any of them
}