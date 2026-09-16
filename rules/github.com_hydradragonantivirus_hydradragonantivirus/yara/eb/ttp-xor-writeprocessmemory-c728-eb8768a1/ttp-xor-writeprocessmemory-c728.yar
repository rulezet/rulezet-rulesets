rule TTP_XOR_WriteProcessMemory_c728 {
  strings:
    $key_c728 = { 90 5a [2] a2 78 [2] a4 4d [2] 8a 4d [2] b5 51 }

  condition:
    any of them
}