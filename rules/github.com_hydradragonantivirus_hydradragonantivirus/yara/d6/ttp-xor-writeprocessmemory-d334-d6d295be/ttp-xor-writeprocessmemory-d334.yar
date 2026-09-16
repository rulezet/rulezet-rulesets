rule TTP_XOR_WriteProcessMemory_d334 {
  strings:
    $key_d334 = { 84 46 [2] b6 64 [2] b0 51 [2] 9e 51 [2] a1 4d }

  condition:
    any of them
}