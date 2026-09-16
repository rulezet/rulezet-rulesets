rule TTP_XOR_WriteProcessMemory_d031 {
  strings:
    $key_d031 = { 87 43 [2] b5 61 [2] b3 54 [2] 9d 54 [2] a2 48 }

  condition:
    any of them
}