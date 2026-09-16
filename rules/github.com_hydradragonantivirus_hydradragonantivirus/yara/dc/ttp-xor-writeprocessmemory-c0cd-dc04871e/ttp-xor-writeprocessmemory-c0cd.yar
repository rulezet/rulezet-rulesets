rule TTP_XOR_WriteProcessMemory_c0cd {
  strings:
    $key_c0cd = { 97 bf [2] a5 9d [2] a3 a8 [2] 8d a8 [2] b2 b4 }

  condition:
    any of them
}