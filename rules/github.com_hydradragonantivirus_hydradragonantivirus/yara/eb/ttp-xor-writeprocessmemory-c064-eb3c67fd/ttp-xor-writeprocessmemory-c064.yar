rule TTP_XOR_WriteProcessMemory_c064 {
  strings:
    $key_c064 = { 97 16 [2] a5 34 [2] a3 01 [2] 8d 01 [2] b2 1d }

  condition:
    any of them
}