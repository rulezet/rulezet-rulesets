rule TTP_XOR_WriteProcessMemory_c3cd {
  strings:
    $key_c3cd = { 94 bf [2] a6 9d [2] a0 a8 [2] 8e a8 [2] b1 b4 }

  condition:
    any of them
}