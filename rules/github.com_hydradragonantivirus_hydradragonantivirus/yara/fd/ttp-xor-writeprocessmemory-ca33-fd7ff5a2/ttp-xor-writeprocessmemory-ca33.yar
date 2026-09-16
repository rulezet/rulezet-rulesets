rule TTP_XOR_WriteProcessMemory_ca33 {
  strings:
    $key_ca33 = { 9d 41 [2] af 63 [2] a9 56 [2] 87 56 [2] b8 4a }

  condition:
    any of them
}