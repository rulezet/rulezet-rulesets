rule TTP_XOR_WriteProcessMemory_c6cd {
  strings:
    $key_c6cd = { 91 bf [2] a3 9d [2] a5 a8 [2] 8b a8 [2] b4 b4 }

  condition:
    any of them
}