rule TTP_XOR_WriteProcessMemory_c613 {
  strings:
    $key_c613 = { 91 61 [2] a3 43 [2] a5 76 [2] 8b 76 [2] b4 6a }

  condition:
    any of them
}