rule TTP_XOR_WriteProcessMemory_c10d {
  strings:
    $key_c10d = { 96 7f [2] a4 5d [2] a2 68 [2] 8c 68 [2] b3 74 }

  condition:
    any of them
}