rule TTP_XOR_WriteProcessMemory_c428 {
  strings:
    $key_c428 = { 93 5a [2] a1 78 [2] a7 4d [2] 89 4d [2] b6 51 }

  condition:
    any of them
}